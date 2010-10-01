# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{devise_oauth_provider}
  s.version = "0.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Nick Marfleet"]
  s.date = %q{2010-01-26}
  s.description = %q{Gem to enable oauth provisioning through devise}
  s.email = %q{nick@sct.com.au}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".document",
     ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "VERSION",
     "devise_oauth_provider.gemspec",
     "lib/devise_oauth_provider.rb",
     "lib/devise_oauth_provider/controllers/filters.rb",
     "lib/devise_oauth_provider/strategy.rb",
     "test/helper.rb",
     "test/test_devise_oauth_provider.rb"
  ]
  s.homepage = %q{http://github.com/nickm/devise_oauth_provider}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Gem to enable oauth provisioning through devise}
  s.test_files = [
    "test/helper.rb",
     "test/test_devise_oauth_provider.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    else
      s.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    end
  else
    s.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
  end
end

