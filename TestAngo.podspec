Pod::Spec.new do |s|
  s.name         = "TestAngo"
  s.version      = "0.0.3"
  s.summary      = "よく使う日付関係の関数"
  s.description  = <<-DESC
                   よく使う日付関数
                   DESC

  s.homepage     = "https://github.com/test123jpjpjp/ango"

  s.license      = { :type => "MIT", :file => "LICENSE" }

  s.author             = { "Ebina" => "http://ez-net.jp/profile/" }
  s.social_media_url   = "http://twitter.com/es_kumagai"

  s.ios.deployment_target = "11.0"

  s.source       = { :git => "https://github.com/test123jpjpjp/ango.git" }
  s.source_files  = "TestAngo/**/*.swift"
end
