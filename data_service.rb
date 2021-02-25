class DataService
  attr_reader :data, :year,
              :nist, :redhat, :microsoft

  def initialize(args = {})
    @data = @year = @nist = @nist_nulls = nil
    @redhat = @micrsoft = @ms_transform = nil

    if args[:nist].blank? && !args[:year].blank?
      @year = args[:year].to_i
      nist_array= JSON.parse(NistGateway.cve_file_for(@year))['CVE_Items']
      init_keys(nist_array)
      @data = @nist = nist_array
      @nist_nulls = find_nulls(@nist)
    end

    if !args[:nist].blank? && args[:nist].is_a?(Array) && !args[:year].blank?
      @year = args[:year].to_i
      nist_array = args[:nist]
      init_keys(nist_array)
      @data = @nist = nist_array
      @nist_nulls = find_nulls(@nist)
    end
  end

  def run(year)
    get_redhat
    merge_redhat
    year = Time.now.year if year == 'modified'
    if year.to_i >= MICROSOFT_OLDEST_YEAR
      get_microsoft(year)
      merge_microsoft
    else
      logger.console "* No MS data available before #{MICROSOFT_OLDEST_YEAR}."
    end
    self
  end

  def get_redhat
    rh_params = Redhat.make_rh_params(@nist_nulls)
    num_requested = Redhat.count_get_ids(rh_params)
    logger.console '* RedHat: downloading.. '
    starting_time = Time.now
    rh_updated_cves = []
    rh_params.each.with_index(1) do |ids_string, chunk_num|
      logger.console "\t#{chunk_num} of #{rh_params.size}: "
      response_body = HttpsGet.run(url: REDHAT_SECDATA_URL,
                                   params: { ids: ids_string })
      begin
        rh_json = JSON.parse(response_body)
        rh_updated_cves.push(rh_json)
        logger.console "\t\t#{rh_json.size} found in #{(Time.now - starting_time).round(2)} sec. "
      rescue => e
        logger.error "** Error parsing RH JSON (#{cvrf_doc_id}):\n" \
                       "#{e.message}\n" + e.backtrace.first(20).join("\n")
        next
      end
    end
    rh_updated_cves.flatten!
    logger.console "RedHat: Received #{rh_updated_cves.size} from #{num_requested} requested " \
         "in #{(Time.now - starting_time).round(2)} seconds."
    @redhat = rh_updated_cves
  end

  def merge_redhat
    if @redhat.blank?
      logger.console 'no Redhat data for missing NIST scores'
      return
    end
    data2 = @data.deep_dup
    @data = Redhat.update_with_rh_data(data2, @redhat)
  end

  def merge_microsoft
    if @ms_transform.blank?
      logger.console 'no MS data for missing NIST scores'
      return
    end
    data2 = @data.deep_dup
    @data = Microsoft.update_with_ms_data(data2, @ms_transform)
  end

  def set_redhat(redhat_data)
    @redhat = redhat_data unless redhat_data.blank?
  end

  def set_microsoft(raw_ms_data)
    ary = []
    ary.push raw_ms_data unless raw_ms_data.is_a? Array
    @microsoft = ary unless raw_ms_data.blank?
    @ms_transform = Microsoft.transform_ms_data(@microsoft, @nist_nulls)
  end

  def get_microsoft(cve_year = @year)
    raw_ms_data = []
    months = MICROSOFT_MONTHS
    this_month = Time.now.month.to_i
    this_year = Time.now.year.to_i
    starting_time = Time.now
    logger.console "\n* Microsoft: downloading..\n"
    months.each.with_index(1) do |month, i|
      if (i > this_month) && (this_year == cve_year) then next end
      cvrf_doc_id = "#{cve_year}-#{month}"
      logger.console "\t#{cvrf_doc_id}.. "
      url_string = "#{MICROSOFT_CVRF_BASE_URL}/#{cvrf_doc_id}"
      response_body = HttpsGet.run(url: url_string,
                                   params: { 'api-version' => MICROSOFT_API_VERSION },
                                   headers: { 'api-key' => MICROSOFT_CVRF_API_KEY,
                                              'Accept' => 'application/json' },
                                   tls_version: TLS_VERSION)
      begin
        response_hash = JSON.parse(response_body)
        raw_ms_data.push(response_hash)
      rescue => e
        logger.error "** Error parsing MS JSON (#{cvrf_doc_id}):\n" \
                       "#{e.message}" + e.backtrace.first(20).join("\n")
        next
      end

    end
    logger.console "Microsoft: Received #{raw_ms_data.size} months in " \
         "#{(Time.now - starting_time).round(2)} seconds for #{cve_year}."
    @microsoft = raw_ms_data
    @ms_transform = Microsoft.transform_ms_data(@microsoft, @nist_nulls)
  end

  private

  def find_nulls(cve_items)
    missing_scores = []
    cve_items.each do |cve_item|
      cve_id = cve_item.dig('cve', 'CVE_data_meta', 'ID')
      cve_v3_score = cve_item.dig('impact', 'metric', 'cvss', 'baseScore')
      if !cve_id.nil? && (cve_v3_score.nil? || !is_numeric?(cve_v3_score))
        missing_scores.push(cve_id)
      end
    end
    missing_scores
  end

  def init_keys(cve_items)
    cve_items.map do |cve_item|
      cve_item['impact'] = {} if cve_item['impact'].blank?
      cve_item['impact']['metric'] = {} if cve_item['impact']['metric'].blank?
      if cve_item['impact']['metric']['cvss'].blank?
        cve_item['impact']['metric']['cvss'] = {}
      end
      if cve_item['impact']['metric']['cvss']['baseSeverity'].blank?
        cve_item['impact']['metric']['cvss']['baseSeverity'] = 'Null'
      end
      if cve_item['cve']['description']['description_data'].blank?
        cve_item['cve']['description']['description_data'] = []
      end
      if cve_item['cve']['description']['description_data'][0].blank?
        cve_item['cve']['description']['description_data'][0] = {}
      end
      if cve_item['cve']['description']['description_data'][0]['value'].blank?
        cve_item['cve']['description']['description_data'][0]['value'] = ''
      end
      cve_item['cve']['problemtype'] = {} if cve_item['cve']['problemtype'].blank?
      if cve_item['cve']['problemtype']['problemtype_data'].blank?
        cve_item['cve']['problemtype']['problemtype_data'] = []
      end
      if cve_item['cve']['problemtype']['problemtype_data'][0].blank?
        cve_item['cve']['problemtype']['problemtype_data'][0] = {}
      end
      if cve_item['cve']['problemtype']['problemtype_data'][0]['description'].blank?
        cve_item['cve']['problemtype']['problemtype_data'][0]['description'] = []
      end
      if cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0].blank?
        cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0] = {}
      end
      if cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'].blank?
        cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] = ''
      end
      if cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'].blank?
        cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] = ''
      end
    end
  end

  def is_numeric?(arg)
    !Float(arg).nil?
  rescue
    false
  end
end
