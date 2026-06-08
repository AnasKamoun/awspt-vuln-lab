# Intentionally vulnerable Sinatra-style lab for SAST validation. DO NOT DEPLOY.
require 'sinatra'
require 'yaml'
require 'erb'
require 'open-uri'
require 'open3'
require 'sqlite3'
require 'jwt'
require 'net/ldap'

# Hardcoded FAKE secrets (CWE-798: Use of Hard-coded Credentials)
AWS_SECRET_ACCESS_KEY = 'AKIA4HG7EXAMPLE9XYZ/wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY'.freeze
STRIPE_API_KEY = 'sk_live_51HxQz2eZvKYlo2C9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd'.freeze
JWT_HMAC_SECRET = 'super_s3cret_signing_key_do_not_share_2024'.freeze

DB = SQLite3::Database.new(':memory:')

# CWE-95: Code Injection via eval of attacker-controlled input
get '/eval' do
  code = params[:code]
  eval(code)
end

# CWE-78: OS Command Injection via system() interpolation
get '/ping' do
  host = params[:host]
  system("ping -c 1 #{host}")
end

# CWE-78: OS Command Injection via backtick subshell
get '/dig' do
  domain = params[:domain]
  `dig #{domain} +short`
end

# CWE-78: OS Command Injection via %x[] interpolation
get '/trace' do
  target = params[:target]
  %x[traceroute #{target}]
end

# CWE-78: OS Command Injection via Open3 with shell string
get '/whois' do
  q = params[:q]
  out, _err, _st = Open3.capture3("whois #{q}")
  out
end

# CWE-502: Deserialization of Untrusted Data via YAML.load
post '/yaml' do
  data = params[:data]
  obj = YAML.load(data)
  obj.inspect
end

# CWE-502: Deserialization of Untrusted Data via Marshal.load
post '/marshal' do
  blob = request.body.read
  obj = Marshal.load(blob)
  obj.inspect
end

# CWE-89: SQL Injection via string interpolation into execute
get '/user' do
  id = params[:id]
  rows = DB.execute("SELECT * FROM users WHERE id = #{id}")
  rows.to_s
end

# CWE-89: SQL Injection via second-order header value
get '/search' do
  term = request.env['HTTP_X_SEARCH']
  DB.execute("SELECT name FROM products WHERE name LIKE '%#{term}%'").to_s
end

# CWE-918: Server-Side Request Forgery via open()
get '/fetch' do
  url = params[:url]
  open(url).read
end

# CWE-918: SSRF via URI.open on attacker URL
get '/proxy' do
  target = params[:target]
  URI.open(target).read
end

# CWE-94: Server-Side Template Injection via ERB.result
get '/render' do
  tpl = params[:tpl]
  ERB.new(tpl).result(binding)
end

# CWE-22: Path Traversal via unsanitized file read
get '/download' do
  name = params[:file]
  File.read("/var/www/uploads/#{name}")
end

# CWE-22: Path Traversal via File.open write
post '/upload' do
  fname = params[:filename]
  body = request.body.read
  File.open("/srv/data/#{fname}", 'w') { |f| f.write(body) }
  'stored'
end

# CWE-79: Reflected Cross-Site Scripting (unescaped output)
get '/greet' do
  who = params[:name]
  "<html><body><h1>Hello #{who}</h1></body></html>"
end

# CWE-601: Open Redirect via attacker-controlled Location
get '/go' do
  dest = params[:next]
  redirect dest
end

# CWE-90: LDAP Injection via interpolated filter
get '/ldap' do
  uid = params[:uid]
  ldap = Net::LDAP.new(host: 'ldap.internal', port: 389)
  ldap.search(base: 'dc=corp,dc=local', filter: "(uid=#{uid})")
  'searched'
end

# CWE-1336: Server-Side Template Injection via send to arbitrary method
get '/call' do
  meth = params[:method]
  arg = params[:arg]
  'result'.send(meth, arg)
end

# CWE-77: Command Injection via exec of a built command string
get '/convert' do
  src = params[:src]
  dst = params[:dst]
  exec("convert #{src} #{dst}")
end

# CWE-array Mass Assignment / unsafe constantize (CWE-470)
get '/gadget' do
  cls = params[:class]
  Object.const_get(cls).new
end

# CWE-347: Improper JWT verification (decode without signature check) using env token
get '/token' do
  raw = request.env['HTTP_AUTHORIZATION'].to_s.sub('Bearer ', '')
  payload, _h = JWT.decode(raw, nil, false)
  payload.to_s
end

# CWE-77: Command Injection from CLI argument / stdin in standalone mode
if __FILE__ == $PROGRAM_NAME && ARGV[0] == 'cli'
  user_cmd = ARGV[1] || $stdin.gets.to_s.strip
  log_dir = ENV['LOG_DIR'] || '.'
  # taint flows from ARGV/stdin/ENV into system()
  system("sh -c 'echo running; #{user_cmd}' >> #{log_dir}/audit.log")
end
