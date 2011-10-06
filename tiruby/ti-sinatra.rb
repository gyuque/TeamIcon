#!/usr/bin/ruby
# encoding: utf-8
require 'rubygems'
require 'oauth'
require 'redis'
require 'redis/list'
require 'redis/value'
require 'sinatra'
require 'cgi'
require 'rack/csrf'

require 'socket'
BasicSocket.do_not_reverse_lookup = true
enable :sessions

def determine_production()
	begin
		return false if File.exist?("../../../dev-here")
	rescue
	end

	return true
end
require File.expand_path(File.dirname(__FILE__)) + '/thumbnailer'
require File.expand_path(File.dirname(__FILE__)) + '/secret-settings'
PRODUCTION = determine_production()

THIS_SITE = PRODUCTION ? "teamicon-zwqimddc.dotcloud.com" : "127.0.0.1:4567"
def oauth_cs()
	OAuth::Consumer.new(OAUTH_CKEY, OAUTH_CSEC, {
	    :site => "https://api.twitter.com/"
	})
end

def is_admin(uid)
	i = uid.to_i
	# Twitter のユーザID  直書きなんとかしたい
	return true if i == 3608191

	return false
end

def is_shuffle_user(uid)
	i = uid.to_i
	return i == 19289830 || i == 317644784
end

def is_login_admin(ses)
	a = ses[:auth_info]
	return false if not a

	return is_admin(a.params['user_id'])
end

def has_shuffle_permission(ses)
	a = ses[:auth_info]
	return false if not a

	return is_admin(a.params['user_id']) || is_shuffle_user(a.params['user_id'])
end

def ensure_redis
	if not $redis
		if PRODUCTION
			$redis = Redis.new(:port => REDIS_PORT, :host => 'teamicon-ZWQIMDDC.dotcloud.com', :password => REDIS_PASS)
		else
			$redis = Redis.new(:host => '127.0.0.1')
		end
	end
end

# Redis 使ってるのはローカルのインストール楽だったから(なんとかしたい)
class TeamList
	def initialize
		ensure_redis
		@ls = Redis::List.new('teams-list', :marshal => true)
	end

	def add(name)
		@ls.each{|t|
			return false if t['name'] == name
		}

		@ls << {'name' => name}
		return true
	end

	def find(name)
		@ls.each{|t| 
		  return t if t['name'].force_encoding('utf-8') == name }

		return nil
	end

	def list
		@ls
	end
end

class Team
	attr_reader :name

	def initialize(tname)
		ensure_redis

		@name = tname
		@key_name = "team//#{tname}"

		@rv = Redis::Value.new(@key_name, :marshal => true)
		init
	end

	def init
		begin
			i = @rv.value['icons']
		rescue
			@rv.value = {'icons' => [], 'members' => []}
		end
	end

	def icon_list
		@rv.value['icons']
	end

	def members
		@rv.value['members']
	end

	def self.add_icon(tname, image, img_type)
		require 'digest/sha1'
		filehash = Digest::SHA1.hexdigest(image)

		ls = TeamList.new
		thash = ls.find(tname)
		return false if not thash
		
		tm = Team.new(tname)
		tm.set_icon(filehash, image, img_type)

		return true
	end

	def self.remove_icon(tname, iname)
		ls = TeamList.new
		thash = ls.find(tname)
		return false if not thash

		return Team.new(tname).unset_icon(iname)
	end

	def self.mod_member(tname, u, rm)
		ls = TeamList.new
		thash = ls.find(tname)
		return false if not thash

		tm = Team.new(tname)
		if !rm
			tm.set_member(u)
		else
			tm.delete_member(u)
		end

		return true
	end

	def self.add_member(tname, u)
		self.mod_member(tname, u, false)
	end

	def self.remove_member(tname, u)
		self.mod_member(tname, u, true)
	end

	def unset_icon(filehash)
		ls = icon_list
		mls = self.members

		newval = Redis::Value.new(@key_name, :marshal => true)
		newval.value = { 'icons' => ls.select{|h| h['name'] != filehash}, 'members' => mls }
	end

	def set_icon(filehash, image, img_type)
		require 'base64'
		ls = icon_list
		h = nil

		ls.each{|i|
			if i['name'] == filehash
				h = i
				break
			end
		}

		if not h #new
			h = {'name' => filehash} 
			ls << h
		end

		mls = self.members
		newval = Redis::Value.new(@key_name, :marshal => true)
		newval.value = { 'icons' => ls, 'members' => mls }

		imgval = Redis::Value.new(self.class.img_key(filehash))
		imgval.value = Base64.encode64(wrap_ustr(image))

		mimval = Redis::Value.new(self.class.img_mime_key(filehash))
		mimval.value = img_type
	end

	def delete_member(u)
		newls = []
		ls = members
		ls.each{|m|
			newls << m if m['id'].to_i != u['id'].to_i
		}

		ils = self.icon_list
		newval = Redis::Value.new(@key_name, :marshal => true)
		newval.value = { 'icons' => ils, 'members' => newls }
	end

	def set_member(u)
		ls = members
		found = nil
		ls.each{|m|
			if m['id'].to_i == u['id'].to_i
				found = m
				break
			end
		}

		if not found
			found = {'id' => u['id']}
			ls << found
		end

		found['screen_name'] = u['screen_name']
		found['token'] = u['token']
		found['secret'] = u['secret']

		ils = self.icon_list
		newval = Redis::Value.new(@key_name, :marshal => true)
		newval.value = { 'icons' => ils, 'members' => ls }
	end

	def in_team(uid)
		self.members.each{|m|
			return m if m['id'].to_i == uid.to_i
		}

		return nil
	end

	def self.img_key(img_name)
		"image//#{img_name}"
	end

	def self.img_mime_key(img_name)
		"image//#{img_name}//mime"
	end

	def self.img_thumb_key(img_name)
		"image//#{img_name}//thumb"
	end

	def self.update_thumbnail(name, blob)
		require 'base64'
		ensure_redis
		ik = self.img_key(name)
		if $redis.get(ik)
			v = Redis::Value.new(self.img_thumb_key(name))
			v.value = Base64.encode64(wrap_ustr(blob))
		end
	end

	def self.get_icon(name)
		require 'base64'
		ensure_redis
		ik = self.img_key(name)
		ival = $redis.get(ik)
		return nil if not ival

		ress = [Base64.decode64( ival ),
		        Redis::Value.new( self.img_mime_key(name) ).value ]

		thval = $redis.get(self.img_thumb_key(name))
		ress << Base64.decode64(thval) if thval

		return ress
	end
end

def account_disp(ses, retpath = nil)
	if not ses[:auth_info]
		return "<div class=\"account-info oauth-trigger\"><a href=\"/connect\">Twitter アカウントを利用</a></div>"
	else
		return "<div class=\"account-info\">Twitter アカウント: #{ CGI.escapeHTML(ses[:auth_info].params[:screen_name]) } <form id=\"remove-session\" method=\"post\" action=\"/logout\">#{ Rack::Csrf.csrf_tag(env) }<input type=\"submit\" value=\"ログアウト\"></form></div>"
	end
end

error 403 do
  "403 Forbidden"
end

error 404 do
  "404 Not Found"
end

error 400 do
  "400 Bad Request"
end

get '/' do
	require 'uri'
	tlinks = []

	tls = TeamList.new
	tls.list.each{|t|
		tlinks << wrap_ustr("<a href=\"/team/#{ URI.encode(t['name']) }\">#{CGI.escapeHTML(t['name'])}</a>")
	}

	erb :index, :locals => {:ver => APP_VER_STR, :is_pro => PRODUCTION, :tlinks => tlinks, :is_admin => is_login_admin(session), :acc => wrap_ustr(account_disp(session))}
end

# Twitter 認証開始（コールバック前）
get '/connect' do
	cs = oauth_cs

	request_token = cs.get_request_token(:oauth_callback => "http://#{THIS_SITE}/set-token")
	session[:request_token] = request_token.token
	session[:request_token_secret] = request_token.secret
	redirect request_token.authorize_url
end

post '/logout' do
	post_tok = Rack::Csrf.csrf_token(env)
	if params['_csrf'] != post_tok
		return 403
	end

	session[:auth_info] = nil
	redirect '/'
end

# Twitter 認証（コールバック後）
get '/set-token' do
	rt = session[:request_token]
	rs = session[:request_token_secret]
	cs = oauth_cs

	request_token = OAuth::RequestToken.new(cs, rt, rs)
	access_token = request_token.get_access_token({},
	                :oauth_token => params['oauth_token'],
	                :oauth_verifier => params['oauth_verifier'])

	session[:auth_info] = access_token

	redirect '/'
end

get '/ti.css' do
  headers['Cache-Control'] = 'public, max-age=160'
  content_type :css
  send_file "views/ti.css"
end

get '/images/authbar.png' do
  headers['Cache-Control'] = 'public, max-age=600'
  content_type :png
  send_file "images/authbar.png"
end

get '/admin' do
	if not is_login_admin(session)
		return 403
	end
	
	erb :admin, :locals => {:post_tok => Rack::Csrf.csrf_tag(env)}
end

post '/rebuild-thumbnail' do
	return 403 if not is_login_admin(session)
	post_tok = Rack::Csrf.csrf_token(env)
	return 403 if params['_csrf'] != post_tok
	
	iname = params['iname']
	imgdat = Team.get_icon(iname)
	if imgdat
		th = Thumbnailer.direct_generate(imgdat[0])
		Team.update_thumbnail(iname, th)
	else
		return 404
	end

	"ok"
end


post '/team' do
	if not is_login_admin(session)
		return 403
	end

	tname = params['tname']

	tls = TeamList.new
	tls.add(tname)
end

# チーム情報表示（アイコン一覧、メンバー一覧）
get '/team/:tname' do |tname|
	require 'uri'

	flash_message = session[:flash_message]
	session[:flash_message] = nil

	tname = params['tname']
	tls = TeamList.new
	team = tls.find(tname)
	auth = session[:auth_info]
	twname = auth ? CGI.escapeHTML(auth.params[:screen_name]) : nil

	if not team
		return 404
	end

	team_obj = Team.new(team['name'])
	icon_list   = team_obj.icon_list
	me = auth ? team_obj.in_team(auth.params['user_id']) : nil
	pename = URI.encode(team_obj.name)

	member_vars = team_obj.members.map{|m|
		{'name' => CGI.escapeHTML(m['screen_name'])}
	}

	erb :team, :locals => {:escaped_tname => wrap_tstr(CGI.escapeHTML(team_obj.name)), :twname => twname, :pe_tname => pename, :in_team => !!me,
	            :ticons => icon_list, :members => member_vars, :acc => wrap_tstr(account_disp(session, "/team/#{pename}")), :post_tok => Rack::Csrf.csrf_tag(env),
	            :is_admin => is_login_admin(session), :has_shuffle => has_shuffle_permission(session), :flash_message => flash_message}
end

get '/dyn-image/:name' do |name|
	img = Team.get_icon(name)
	headers['Cache-Control'] = 'public, max-age=1800'
	content_type img[1]
	pthumb = params['prefer_thumb'] && (params['prefer_thumb'].to_i == 1)

	return img[2] if pthumb && img.length > 2 && img[2]
	img[0]
end

post '/dyn-image' do
	if not is_login_admin(session)
		return 403
	end

	post_tok = Rack::Csrf.csrf_token(env)
	if params['_csrf'] != post_tok
		return 403
	end

	upfile = params[:file][:tempfile]
	body = upfile.read
	if body.length > 1048576
		STDERR.puts("Too large")
		return 400
	end

	img_type = check_image_magic(body)
	if not img_type
		STDERR.puts("Bad File Type")
		return 400
	end

	Team.add_icon(params['tname'].force_encoding('utf-8'), body, img_type)
	"ok"
end

post '/remove-team-icon' do
	# check ---
	if not is_login_admin(session)
		return 403
	end

	post_tok = Rack::Csrf.csrf_token(env)
	if params['_csrf'] != post_tok
		return 403
	end

	iname = params['iname']
	if !iname || iname.length < 1
		return 400
	end
	# check ---

	tname = params['tname'].force_encoding('utf-8')
	Team.remove_icon(tname, iname)
	redirect "/team/#{ URI.encode(tname) }"
end

post '/use-team-icon' do
	post_tok = Rack::Csrf.csrf_token(env)
	auth = session[:auth_info]
	return 403 if params['_csrf'] != post_tok
	return 403 if not auth

	require './icon-api'
	cs = oauth_cs
	image_info = Team.get_icon(params['iname'])
	update_profile_image(image_info[0], image_info[1], cs, auth.token, auth.secret)

	tname = params['tname']
	session[:flash_message] = "icon.used" if tname
	redirect tname ? "/team/#{ URI.encode(tname.force_encoding('utf-8')) }" : '/'
end

post '/team/member' do
	require 'uri'
	post_tok = Rack::Csrf.csrf_token(env)
	if params['_csrf'] != post_tok
		return 403
	end

	auth = session[:auth_info]
	if not auth
		return 403
	end

	u = {
		'id' => auth.params['user_id'],
		'screen_name' => auth.params['screen_name'],
		'token' => auth.token,
		'secret' => auth.secret
	}

	tname = params['tname'].force_encoding('utf-8')
	if params['op'] == 'delete'
		Team.remove_member(tname, u)
	else
		Team.add_member(tname, u)
	end

	redirect "/team/#{ URI.encode(tname) }"
end

post '/run-shuffle' do
	if not has_shuffle_permission(session)
		return 403
	end

	tname = params['tname'].force_encoding('utf-8')
	post_tok = Rack::Csrf.csrf_token(env)
	if params['_csrf'] != post_tok
		return 403
	end

	ls = TeamList.new
	thash = ls.find(tname)
	if not thash
		return 404
	end

	tm = Team.new(tname)
	icon_ls = shuffle_icons(tm.icon_list)

	m_index = 0
	tm.members.each{|mb|
		icon_index = m_index % icon_ls.length
		change_icon(mb['token'], mb['secret'],
		  Team.get_icon( icon_ls[icon_index]['name'] ))

		m_index += 1
	}

	"ok"
end

def shuffle_icons(ls)
	src = ls.clone

	ret = []
	src.length.times{
		i = rand(src.length)
		ret << src.delete_at(i)
	}

	return ret
end

def change_icon(token, secret, image_info)
	cs = oauth_cs
	require './icon-api'

	update_profile_image(image_info[0], image_info[1], cs, token, secret)
end

# 画像の種類のいい加減なチェック
def check_image_magic(body)
	b1 = body.getbyte(0)

	return 'image/png'  if b1 == 137
	return 'image/jpeg' if b1 == 255
	return 'image/gif'  if b1 == 71

	return nil
end

def wrap_ustr(s)
	s.dup.force_encoding('ASCII-8BIT')
end

# ローカルの sinatra が腐ってる対策なんとかしたい
def wrap_tstr(s)
	if PRODUCTION
		return s.dup.force_encoding('utf-8')
	else
		return wrap_ustr(s)
	end
end
