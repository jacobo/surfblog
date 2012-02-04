class Admin::SessionsController < ApplicationController
  layout 'login'

  def show
    if using_open_id?
      create
    else
      redirect_to :action => 'new'
    end
  end

  def new
    render :text => params.inspect
    # require 'oauth2'
    client_id = "f3c1db38c7d34934f239"
    client_secret = "8330407e03de5dfff4023ae1eeacd59e745afcb6"
#
# https://github.com/login/oauth/authorize?response_type=code&client_id=f3c1db38c7d34934f239&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback
#
#
# POST https://github.com/login/oauth/access_token?
#   client_id=...&
#   redirect_uri=http://www.example.com/oauth_redirect&
#   client_secret=...&
#   code=...
#
    require 'oauth2'
    client = OAuth2::Client.new(client_id, client_secret, :site => 'https://github.com', :authorize_url => '/login/oauth/authorize', :token_url => "/login/oauth/access_token")
    client.auth_code.authorize_url(:redirect_uri => 'http://localhost:3000/auth/callback')
#
#
    token = client.auth_code.get_token('26e8e05be8fc29761f7c', :redirect_uri => 'http://localhost:3000/auth/callback')

    # response = token.get('/api/resource', :params => { 'query_foo' => 'bar' })

    curl -v -X POST "https://github.com/login/oauth/access_token?client_id=f3c1db38c7d34934f239&redirect_uri=http://localhost:3000/auth/callback&client_secret=8330407e03de5dfff4023ae1eeacd59e745afcb6&code=221a75b8b043befb3aef"

    token.token

    token.get("/api/v2/json/user/show?access_token=#{token.token}")
    #or any other way to GET to this URL

  curl -v -X GET "https://github.com/api/v2/json/user/show?access_token=e2898a055ccad7356eda98cba1749706141d5a1c"

#
#     GET https://github.com/api/v2/json/user/show?access_token=...

"https://github.com/api/v2/json/user/show?access_token=e2898a055ccad7356eda98cba1749706141d5a1c"

  end

  def create
    return successful_login if allow_login_bypass? && params[:bypass_login]

    if params[:openid_url].blank? && !request.env[Rack::OpenID::RESPONSE]
      flash.now[:error] = "You must provide an OpenID URL"
      render :action => 'new'
    else
      authenticate_with_open_id(params[:openid_url]) do |result, identity_url|
        if result.successful?
          if enki_config.author_open_ids.include?(URI.parse(identity_url))
            return successful_login
          else
            flash.now[:error] = "You are not authorized"
          end
        else
          flash.now[:error] = result.message
        end
        render :action => 'new'
      end
    end
  end

  def destroy
    session[:logged_in] = false
    redirect_to('/')
  end

protected

  def successful_login
    session[:logged_in] = true
    redirect_to(admin_root_path)
  end

  def allow_login_bypass?
    %w(development test).include?(Rails.env)
  end
  helper_method :allow_login_bypass?
end
