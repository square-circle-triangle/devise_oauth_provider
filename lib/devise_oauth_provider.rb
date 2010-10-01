# encoding: utf-8
begin
  require 'devise'
  require 'oauth'
rescue
  gem 'devise'
  require 'devise'
end

require File.expand_path(File.dirname(__FILE__) + "/devise_oauth_provider/controllers/filters") 
require File.expand_path(File.dirname(__FILE__) + "/devise_oauth_provider/strategy")

Devise.add_module(:oauth_provider, :strategy => true, :controller => :oauth)