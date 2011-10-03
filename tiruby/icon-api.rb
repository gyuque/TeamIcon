CRLF = "\r\n"
# https://gist.github.com/97756

#Encodes the request as multipart
def add_multipart_data(req,params, mime)
  boundary = Time.now.to_i.to_s(16)
  req["Content-Type"] = "multipart/form-data; boundary=#{boundary}"
  body = ""
  params.each do |key,value|
    esc_key = CGI.escape(key.to_s)
    body << "--#{boundary}#{CRLF}"
    if value.respond_to?(:read)
      body << "Content-Disposition: form-data; name=\"#{esc_key}\"; filename=\"teamicon-#{rand(100000)}\"#{CRLF}"
      body << "Content-Type: #{mime}#{CRLF*2}"
      body << value.read
    else
      body << "Content-Disposition: form-data; name=\"#{esc_key}\"#{CRLF*2}#{value}"
    end
    body << CRLF
  end
  body << "--#{boundary}--#{CRLF*2}"
  req.body = body
  req["Content-Length"] = req.body.size
end

#Uses the OAuth gem to add the signed Authorization header
def add_oauth(req, consumer, atok, asec)
  access_token = OAuth::AccessToken.new(consumer, atok, asec)
  consumer.sign!(req, access_token)
end

def update_profile_image(image_body, mime, consumer, atok, asec)
	require 'open-uri'
	require 'net/http'
	require 'net/https'
	require 'stringio'

	image_file = StringIO.open(image_body)
	url = URI.parse('https://api.twitter.com/1/account/update_profile_image.json')
	net = Net::HTTP.new(url.host, url.port)
	net.use_ssl = true
	net.start do |http|
		req = Net::HTTP::Post.new(url.request_uri)
		add_multipart_data(req, {:image=>image_file}, mime)
		add_oauth(req, consumer, atok, asec)
		res = http.request(req)
		STDERR.puts res.body
	end
end
