require "sinatra"
require "tilt/erb"
require "fileutils"
require "rack/flash"
require "oauth"
require "json"

CONFIG = JSON.parse(File.read(File.expand_path("../config.json", __FILE__)), symbolize_names: true).freeze

set :public_folder, CONFIG[:data]
use Rack::Session::Cookie, { expire_after: (86400 * 7),
                             secret: CONFIG[:secret] }
use Rack::Flash

def logged_in?
  !!session[:user_id]
end

def consumer
  $consumer ||= OAuth::Consumer.new(CONFIG[:oauth][:consumer_key],
                                    CONFIG[:oauth][:consumer_secret],
                                    site: "https://api.twitter.com",
                                    authorize_path: "/oauth/authenticate")
end

def authenticate!
  redirect "/" unless session[:user_id]
end

get "/" do
  if logged_in?
    ids = Dir.glob(File.join(CONFIG[:data], session[:user_id], "*")).map { |path| path.split("/").last }
    erb :index, locals: { ids: ids, user_id: session[:user_id] }
  else
    req = consumer.get_request_token(oauth_callback: request.url.sub(/\/[^\/]*\z/, "/callback"))
    session[:req] = JSON.generate(token: req.token, secret: req.secret)
    redirect req.authorize_url
  end
end

get "/callback" do
  if session[:req]
    json = JSON.parse(session.delete(:req), symbolize_names: true)
    if params[:oauth_token] == json[:token]
      req = OAuth::RequestToken.new(consumer, json[:token], json[:secret])
      acc = req.get_access_token(oauth_verifier: params[:oauth_verifier])
      session[:user_id] = acc.params[:user_id]
      session[:acc] = JSON.generate(token: acc.token, secret: acc.secret)
      FileUtils.mkdir_p(File.join(CONFIG[:data], session[:user_id]))
    end
  end
  redirect "/"
end

post "/update" do
  authenticate!
  return 400 unless /\A[0-9]+-[a-f0-9]{40}\z/ =~ params[:id].to_s
  path = File.join(CONFIG[:data], session[:user_id], params[:id])
  return 404 unless File.exist?(path)

  encoded = [File.read(path)].pack("m0")

  json = JSON.parse(session[:acc], symbolize_names: true)
  acc = OAuth::AccessToken.new(consumer, json[:token], json[:secret])
  acc.post("/1.1/account/update_profile_image.json", image: encoded)

  flash[:notice] = "Successfully updated"
  redirect "/"
end

post "/upload" do
  authenticate!
  return 400 unless (params.dig(:file, :tempfile) rescue nil)
  tempfile = params[:file][:tempfile]
  return 400 if tempfile.size > 5 * 1024 * 1024
  digest = Digest::SHA1.file(tempfile).hexdigest
  id = Time.now.to_i.to_s + "-" + digest
  File.write(File.join(CONFIG[:data], session[:user_id], id), tempfile.read)

  flash[:notice] = "Successfully uploaded"
  redirect "/"
end
