module HttpsGet
  def self.run(args = {})
    if args.blank? || args.with_indifferent_access[:url].blank?
      return 1
    else
      args.symbolize_keys!
    end
    tls_version = args[:tls_version].blank? ? TLS_VERSION.to_sym : args[:tls_version]
    response = nil
    attempts = 3
    attempt = 0
    secs_multiplier = 3
    while attempt < attempts
      secs = attempt*secs_multiplier
      attempt += 1
      begin
        uri = URI.parse(args[:url])
        uri.query = URI.encode_www_form(args[:params].to_a) unless args[:params].blank?
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.ssl_version = tls_version
        request = Net::HTTP::Get.new(uri)
        args[:headers].keys.each { |key, value| request[key] = args[:headers][key] } unless args[:headers].blank?
        response = http.request(request)
        response.blank? ? (logger.console 'no response') : (logger.console "[http #{response.code.to_i}]")
        break
      rescue => e
        logger.console " http #{response.status}" unless response.blank?
        secs = 3*attempt
        message = "#{self}: Connection error (#{attempt} of 3) #{uri}, waiting #{secs} secs:\n" \
                  "#{e.message}\n" + e.backtrace.join("\n")
        logger.console message
        logger.error message
        sleep secs
      end
    end
    response.body
  end
end
