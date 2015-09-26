require 'sinatra/base'
require 'mysql2'
require 'mysql2-cs-bind'
require 'tilt/erubis'
require 'erubis'
require 'dalli'

module Isucon5
  class AuthenticationError < StandardError; end
  class PermissionDenied < StandardError; end
  class ContentNotFound < StandardError; end
  module TimeWithoutZone
    def to_s
      strftime("%F %H:%M:%S")
    end
  end
  ::Time.prepend TimeWithoutZone
end

class Isucon5::WebApp < Sinatra::Base
  use Rack::Session::Cookie
  set :erb, escape_html: true
  set :public_folder, File.expand_path('../../static', __FILE__)
  #set :sessions, true
  set :session_secret, ENV['ISUCON5_SESSION_SECRET'] || 'beermoris'
  set :protection, true

  helpers do
    def config
      @config ||= {
        db: {
          host: ENV['ISUCON5_DB_HOST'] || 'localhost',
          port: ENV['ISUCON5_DB_PORT'] && ENV['ISUCON5_DB_PORT'].to_i,
          username: ENV['ISUCON5_DB_USER'] || 'root',
          password: ENV['ISUCON5_DB_PASSWORD'],
          database: ENV['ISUCON5_DB_NAME'] || 'isucon5q',
        },
      }
    end

    def db
      return Thread.current[:isucon5_db] if Thread.current[:isucon5_db]
      client = Mysql2::Client.new(
        host: config[:db][:host],
        port: config[:db][:port],
        username: config[:db][:username],
        password: config[:db][:password],
        database: config[:db][:database],
        reconnect: true,
      )
      client.query_options.merge!(symbolize_keys: true)
      Thread.current[:isucon5_db] = client
      client
    end

    def memcache
      return Thread.current[:isucon5_memcache] if Thread.current[:isucon5_memcache]
      options = { :namespace => "isucon", :compress => true }
      client = Dalli::Client.new('localhost:11211', options)
      Thread.current[:isucon5_memcache] = client
      client
    end

    def authenticate(email, password)
      query = <<SQL
SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)
SQL
      result = db.xquery(query, email, password).first
      unless result
        raise Isucon5::AuthenticationError
      end
      session[:user_id] = result[:id]
      result
    end

    def current_user
      return @user if @user
      unless session[:user_id]
        return nil
      end
      @user = db.xquery('SELECT id, account_name, nick_name, email FROM users WHERE id=?', session[:user_id]).first
      unless @user
        session[:user_id] = nil
        session.clear
        raise Isucon5::AuthenticationError
      end
      @user
    end

    def authenticated!
      unless current_user
        redirect '/login'
      end
    end

    def get_user(user_id)
      user = db.xquery('SELECT * FROM users WHERE id = ?', user_id).first
      raise Isucon5::ContentNotFound unless user
      user
    end

    def get_user_list(user_id_list)
      user_list = db.xquery('SELECT id, account_name, nick_name FROM users WHERE id IN (?)', user_id_list)
      raise Isucon5::ContentNotFound unless user_list
      user_list
    end

    def get_friend_ids(user_id)
      key = "f_ids_#{user_id}"
      cached_friend_ids = memcache.get(key)
      return cached_friend_ids if cached_friend_ids
      friends_query = 'SELECT another FROM relations WHERE one = ? ORDER BY created_at DESC'
      user_friend_ids = db.xquery(friends_query, user_id).map{ |friend| friend[:another] }
      memcache.set(key, user_friend_ids)
      user_friend_ids
    end

    def clear_friend_ids_cache(user_id)
      key = "f_ids_#{user_id}"
      memcache.delete(key)
    end

    def get_my_friend_ids
      get_friend_ids(current_user[:id])
    end

    def user_from_account(account_name)
      user = db.xquery('SELECT * FROM users WHERE account_name = ?', account_name).first
      raise Isucon5::ContentNotFound unless user
      user
    end

    def is_friend?(another_id)
      my_friend_ids = get_my_friend_ids()
      my_friend_ids.include?(another_id)
=begin
      user_id = session[:user_id]
      query = 'SELECT COUNT(1) AS cnt FROM relations WHERE (one = ? AND another = ?) OR (one = ? AND another = ?)'
      cnt = db.xquery(query, user_id, another_id, another_id, user_id).first[:cnt]
      cnt.to_i > 0 ? true : false
=end
    end

    def is_friend_account?(account_name)
      is_friend?(user_from_account(account_name)[:id])
    end

    def permitted?(another_id)
      another_id == current_user[:id] || is_friend?(another_id)
    end

    def mark_footprint(user_id)
      if user_id != current_user[:id]
        query = 'INSERT INTO footprints (user_id,owner_id) VALUES (?,?)'
        db.xquery(query, user_id, current_user[:id])
      end
    end

    PREFS = %w(
      未入力
      北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 新潟県 富山県
      石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 奈良県 和歌山県 鳥取県 島根県
      岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 熊本県 大分県 宮崎県 鹿児島県 沖縄県
    )
    def prefectures
      PREFS
    end
  end

  error Isucon5::AuthenticationError do
    session[:user_id] = nil
    halt 401, erubis(:login, layout: false, locals: { message: 'ログインに失敗しました' })
  end

  error Isucon5::PermissionDenied do
    halt 403, erubis(:error, locals: { message: '友人のみしかアクセスできません' })
  end

  error Isucon5::ContentNotFound do
    halt 404, erubis(:error, locals: { message: '要求されたコンテンツは存在しません' })
  end

  get '/login' do
    session.clear
    erb :login, layout: false, locals: { message: '高負荷に耐えられるSNSコミュニティサイトへようこそ!' }
  end

  post '/login' do
    authenticate params['email'], params['password']
    redirect '/'
  end

  get '/logout' do
    session[:user_id] = nil
    session.clear
    redirect '/login'
  end

  get '/' do
    authenticated!

    profile = db.xquery('SELECT * FROM profiles WHERE user_id = ?', current_user[:id]).first

    entries_query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
    my_entries = db.xquery(entries_query, current_user[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }

    my_entry_ids_query = 'SELECT id FROM entries WHERE user_id = ? ORDER BY created_at'
    my_entry_ids = db.xquery(my_entry_ids_query, current_user[:id]).map { |entry| entry[:id] }
    comments_for_me_query = "SELECT id, entry_id, user_id, comment, created_at FROM comments WHERE entry_id IN (?) ORDER BY created_at DESC LIMIT 10"
    comments_for_me = db.xquery(comments_for_me_query, my_entry_ids)

   entries_of_friends = []
   id_list = []
   db.query('SELECT id,user_id FROM entries ORDER BY created_at DESC LIMIT 1000').each do |entry|
     next unless is_friend?(entry[:user_id])
     id_list << entry[:id]
     break if id_list.size >= 10
   end
   query = 'SELECT * FROM entries WHERE id IN (?)'
   entries_of_friends = db.xquery(query, id_list)
   entries_of_friends.each do |entry|
     entry[:title] = entry[:body].split(/\n/).first
   end

=begin
   entries_of_friends = []
   db.query('SELECT * FROM entries ORDER BY created_at DESC LIMIT 1000').each do |entry|
     next unless is_friend?(entry[:user_id])
     entry[:title] = entry[:body].split(/\n/).first
     entries_of_friends << entry
     break if entries_of_friends.size >= 10
   end
=end

    comments_of_friends = []
    db.query('SELECT * FROM comments ORDER BY created_at DESC LIMIT 1000').each do |comment|
      next unless is_friend?(comment[:user_id])
      entry = db.xquery('SELECT * FROM entries WHERE id = ?', comment[:entry_id]).first
      entry[:is_private] = (entry[:private] == 1)
      next if entry[:is_private] && !permitted?(entry[:user_id])
      comments_of_friends << comment
      break if comments_of_friends.size >= 10
    end

=begin
    friends_query = 'SELECT * FROM relations WHERE one = ? ORDER BY created_at DESC'
    my_friends = db.xquery(friends_query, current_user[:id]);
    friends_map = {}
    my_friends.each do |rel|
      key = (rel[:one] == current_user[:id] ? :another : :one)
      friends_map[rel[key]] ||= rel[:created_at]
    end
    friends = friends_map.map{|user_id, created_at| [user_id, created_at]}
=end
    friends = get_my_friend_ids()

    query = <<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) AS updated
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 10
SQL
    footprints = db.xquery(query, current_user[:id])

    locals = {
      profile: profile || {},
      entries: my_entries,
      comments_for_me: comments_for_me,
      entries_of_friends: entries_of_friends,
      comments_of_friends: comments_of_friends,
      friends: friends,
      footprints: footprints
    }
    erb :index, locals: locals
  end

  get '/profile/:account_name' do
    authenticated!
    owner = user_from_account(params['account_name'])
    prof = db.xquery('SELECT * FROM profiles WHERE user_id = ?', owner[:id]).first
    prof = {} unless prof
    query = if permitted?(owner[:id])
              'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
            else
              'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :profile, locals: { owner: owner, profile: prof, entries: entries, private: permitted?(owner[:id]) }
  end

  post '/profile/:account_name' do
    authenticated!
    if params['account_name'] != current_user[:account_name]
      raise Isucon5::PermissionDenied
    end
    args = [params['first_name'], params['last_name'], params['sex'], params['birthday'], params['pref']]

    prof = db.xquery('SELECT * FROM profiles WHERE user_id = ?', current_user[:id]).first
    if prof
      query = <<SQL
UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?
SQL
      args << current_user[:id]
    else
      query = <<SQL
INSERT INTO profiles (user_id,first_name,last_name,sex,birthday,pref) VALUES (?,?,?,?,?,?)
SQL
      args.unshift(current_user[:id])
    end
    db.xquery(query, *args)
    redirect "/profile/#{params['account_name']}"
  end

  get '/diary/entries/:account_name' do
    authenticated!
    owner = user_from_account(params['account_name'])
    query = if permitted?(owner[:id])
              'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
            else
              'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :entries, locals: { owner: owner, entries: entries, myself: (current_user[:id] == owner[:id]) }
  end

  get '/diary/entry/:entry_id' do
    authenticated!
    entry = db.xquery('SELECT * FROM entries WHERE id = ?', params['entry_id']).first
    raise Isucon5::ContentNotFound unless entry
    entry[:title], entry[:content] = entry[:body].split(/\n/, 2)
    entry[:is_private] = (entry[:private] == 1)
    owner = get_user(entry[:user_id])
    if entry[:is_private] && !permitted?(owner[:id])
      raise Isucon5::PermissionDenied
    end
    comments = db.xquery('SELECT * FROM comments WHERE entry_id = ?', entry[:id])
    mark_footprint(owner[:id])
    erb :entry, locals: { owner: owner, entry: entry, comments: comments }
  end

  post '/diary/entry' do
    authenticated!
    query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)'
    body = (params['title'] || "タイトルなし") + "\n" + params['content']
    db.xquery(query, current_user[:id], (params['private'] ? '1' : '0'), body)
    redirect "/diary/entries/#{current_user[:account_name]}"
  end

  post '/diary/comment/:entry_id' do
    authenticated!
    entry = db.xquery('SELECT * FROM entries WHERE id = ?', params['entry_id']).first
    unless entry
      raise Isucon5::ContentNotFound
    end
    entry[:is_private] = (entry[:private] == 1)
    if entry[:is_private] && !permitted?(entry[:user_id])
      raise Isucon5::PermissionDenied
    end
    query = 'INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)'
    db.xquery(query, entry[:id], current_user[:id], params['comment'])
    redirect "/diary/entry/#{entry[:id]}"
  end

  get '/footprints' do
    authenticated!
    query = <<SQL
SELECT user_id, owner_id, DATE(created_at) AS date, MAX(created_at) as updated
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id, DATE(created_at)
ORDER BY updated DESC
LIMIT 50
SQL
    footprints = db.xquery(query, current_user[:id])
    user_id_list = footprints.map{|f|f[:owner_id]}
    user_list = get_user_list(user_id_list)
    user_hash = Hash[user_list.map{|u| [u[:id], u]}]
    erb :footprints, locals: { footprints: footprints, user_hash: user_hash }
  end

  get '/friends' do
    authenticated!
    query = 'SELECT * FROM relations WHERE one = ? ORDER BY created_at DESC'
    friends = {}
    db.xquery(query, current_user[:id]).each do |rel|
      key = (rel[:one] == current_user[:id] ? :another : :one)
      friends[rel[key]] ||= rel[:created_at]
    end
    list = friends.map{|user_id, created_at| [user_id, created_at]}
    user_id_list = friends.map{|user_id, created_at| user_id}
    user_list = get_user_list(user_id_list)
    user_hash = Hash[user_list.map{|u| [u[:id], u]}]
    erb :friends, locals: { friends: list, user_hash: user_hash }
  end

  post '/friends/:account_name' do
    authenticated!
    unless is_friend_account?(params['account_name'])
      user = user_from_account(params['account_name'])
      unless user
        raise Isucon5::ContentNotFound
      end
      db.xquery('INSERT INTO relations (one, another) VALUES (?,?), (?,?)', current_user[:id], user[:id], user[:id], current_user[:id])
      clear_friend_ids_cache(current_user[:id])
      clear_friend_ids_cache(user[:id])
      redirect '/friends'
    end
  end

  get '/initialize' do
    memcache.flush
    db.query("DELETE FROM relations WHERE id > 500000")
    db.query("DELETE FROM footprints WHERE id > 500000")
    db.query("DELETE FROM entries WHERE id > 500000")
    db.query("DELETE FROM comments WHERE id > 1500000")
  end
end
