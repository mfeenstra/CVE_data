module Microsoft
  ONLY_NIST_NULLS = true
  def self.get_ms_high_score(cvss_score_set)
    high_score_set = { 'high_score' => 'Null',
                       'vector_string' => 'Null' }
    scores = []
    vector_strings = []
    unless cvss_score_set.empty?
      cvss_score_set.each do |score_info|
        if score_info['BaseScore'].to_f > 0.0
          scores.push score_info['BaseScore'].to_f
          vector_strings.push score_info['Vector'].to_s
        end
      end
    end
    unless scores.empty?
      high_score_set['high_score'] = scores.max
      high_score_set['vector_string'] = vector_strings[scores.rindex(scores.max)]
    end
    high_score_set
  end

  def self.transform_ms_data(ms_data_by_month, nist_missing_scores)
    ms_data = []
    total_ms_cves = 0
    used_ms_cves = 0
    ms_data_by_month.each do |month_data|
      if month_data.key?('message') && month_data['message'].match?('Not authorized')
        logger.error 'Error! transform_ms_data (month_data): Not authorized.'
        next
      end
      if month_data['Vulnerability'].nil?
        logger.console 'transform_ms_data: No data not found for this month.'
        next
      end
      month_data['Vulnerability'].each_with_index do |cve_data, i|
        ms_cve_id = cve_data['CVE']
        total_ms_cves += 1
        if ONLY_NIST_NULLS
          next unless nist_missing_scores.include? ms_cve_id
        end
        description = Nokogiri::HTML(cve_data['Notes'].first['Value']).text.delete("\n")
        threat = cve_data['Threats'].last['Description']['Value'].to_s
        threat_str = if !threat.nil?
                       threat.gsub(';', ' / ').gsub(':', ': ')
                     else
                       ''
                     end
        remedies = ''
        info_str = ''
        cve_data['Remediations'].each do |remedy|
          if (remedy['Type'] == 2) || (remedy['Type'] == 5)
            remedies = "#{remedies}#{remedy['ProductID'].to_s.delete('"')}: (#{remedy['URL']}) "
          end
          next unless (remedy['Type'] == 0) || (remedy['Type'] == 1)
          raw_description = remedy['Description']['Value'].gsub(/<a href=\"(.*)\">(.*)<\/a>/, '\1 \2')
          info_str = "#{info_str}#{Nokogiri::HTML(raw_description).text.delete("\n").tr!('\"', "'")} "
        end
        additional_info = ''
        if info_str.size > 1
          additional_info = "** MORE INFO ** #{info_str}"
        end
        score_result = get_ms_high_score(cve_data['CVSSScoreSets'])
        cvss_score = score_result['high_score'] || 'Null'
        vector_string = score_result['vector_string'] || 'Null'
        cvss_version = if vector_string =~ /^CVSS:(\d+.\d+?)\//
                         Regexp.last_match(1)
                       else
                         'Null'
                       end
        condensed_entry = { ms_cve_id => { :description => "** MICROSOFT ** #{description} " \
                                                           "** THREAT ** #{threat_str} " \
                                                           "#{additional_info} " \
                                                           "** REMEDIATION ** #{remedies} ",
                                           :cvss_score => cvss_score,
                                           :cvss_version => cvss_version,
                                           :vector_string => vector_string } }
        ms_data.push(condensed_entry)
        used_ms_cves += 1
      end
    end
    logger.console "* transform_ms_data: Using #{used_ms_cves} records of #{total_ms_cves} available from Microsoft."
    ms_data
  end

  def self.update_with_ms_data(nist_json, ms_data)
    logger.console "* update_with_ms_data: #{ms_data.size} records:\n\t"
    ms_data.each do |ms_cve|
      nist_json.map do |cve_item|
        next unless ms_cve.key? cve_item['cve']['CVE_data_meta']['ID']
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        logger.console "#{cve_id} "
        if (defined? ms_cve[cve_id][:cvss_score]) &&
             !(is_numeric? cve_item['impact']['metric']['cvss']['baseScore'])
          cve_item['impact']['metric']['cvss']['baseScore'] = ms_cve[cve_id][:cvss_score]
        end
        if (defined? ms_cve[cve_id][:description]) && (ms_cve[cve_id][:description].is_a? String)
          cve_item['cve']['description']['description_data'][0]['value'] =
            "#{cve_item['cve']['description']['description_data'][0]['value']} " \
            "#{ms_cve[cve_id][:description]}"
        end
        if (defined? ms_cve[cve_id][:vector_string]) && (ms_cve[cve_id][:vector_string].is_a? String) &&
           (cve_item['impact']['metric']['cvss']['vectorString'] !~ /^CVSS/)
          cve_item['impact']['metric']['cvss']['vectorString'] = ms_cve[cve_id][:vector_string]
          if ms_cve[cve_id][:cvss3_scoring_vector] =~ /^CVSS:(.+?)\//
            cve_item['impact']['metric']['cvss']['version'] = Regexp.last_match(1)
          end
        end
        cve_item['impact']['metric']['cvss']['source'] = MICROSOFT_SOURCE
        if defined? cve_item['cve']['references']['reference_data'].first['url']
          cve_item['impact']['metric']['cvss']['source'] =
            cve_item['cve']['references']['reference_data'].first['url']
        end
      end
      next
    end
    nist_json
  end

  def self.is_numeric?(arg)
    !Float(arg).nil?
  rescue
    false
  end
end
