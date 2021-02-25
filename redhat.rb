module Redhat
  def self.make_rh_params(nist_missing_scores)
    ids_length = 2048 / 16
    missing_score_chunks = nist_missing_scores.each_slice(ids_length).to_a
    rh_params = []
    missing_score_chunks.each do |cve_list| rh_params.push(cve_list.join(',')) end
    rh_params
  end

  def self.count_get_ids(get_params)
    cves_string = ''
    get_params.each.with_index(1) do |id_string, i|
      cves_string = i < get_params.size ? "#{cves_string}#{id_string}," : "#{cves_string}#{id_string}"
    end
    cves_string.split(',').size
  end

  def self.update_with_rh_data(nist_json, rh_data)
    CpLogger.console "* Updating with RedHat data (#{rh_data.size} total):\n\t"
    rh_data.each do |rh_cve|
      nist_json.map do |cve_item|
        next unless /#{rh_cve['CVE']}/.match?(cve_item['cve']['CVE_data_meta']['ID'])
        CpLogger.console "#{cve_item['cve']['CVE_data_meta']['ID']} "
        cve_item['impact']['metric']['cvss']['baseScore'] = rh_cve['cvss3_score']
        cve_item['impact']['metric']['cvss']['baseSeverity'] = case rh_cve['cvss3_score'].to_f
                                                                       when 0.0..0.099
                                                                         'NONE'
                                                                       when 0.1..3.999
                                                                         'LOW'
                                                                       when 4.0..6.999
                                                                         'MEDIUM'
                                                                       when 7.0..8.999
                                                                         'HIGH'
                                                                       when 9.0..10.0
                                                                         'CRITICAL'
                                                                       else
                                                                         'UNCLASSIFIED'
                                                                       end
        if (defined? rh_cve['cvss3_scoring_vector']) &&
           (rh_cve['cvss3_scoring_vector'].is_a? String) &&
           (rh_cve['cvss3_scoring_vector'].length > 4)
          cve_item = set_scoring_vector(cve_item, rh_cve['cvss3_scoring_vector'])
        end
        # Concatenate additional description (summary)
        if (defined? rh_cve['bugzilla_description']) && (rh_cve['bugzilla_description'].is_a? String)
          cve_item['cve']['description']['description_data'][0]['value'] =
            "#{cve_item['cve']['description']['description_data'][0]['value']} " \
            "** BUGZILLA: #{rh_cve['bugzilla'] || ''} ** #{rh_cve['bugzilla_description']}"
        end
        # CWE data
        if (defined? rh_cve['CWE']) && (rh_cve['CWE'].is_a? String)
          cve_item['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] =
            rh_cve['CWE'].gsub(/[\(\)]/, '').tr('|', ',').gsub('->', ',')
        end
        cve_item['impact']['metric']['cvss']['source'] = REDHAT_SOURCE
        cve_item['impact']['metric']['cvss']['source'] = rh_cve['resource_url'] if
          rh_cve['resource_url'] =~ /redhat\.com/
        next
      end
    end
    nist_json
  end

  def self.metrics_map(code)
    metrics_map_v31 = { 'AV:N' => 'NETWORK',
                        'AV:A' => 'ADJACENT',
                        'AV:L' => 'LOCAL',
                        'AV:P' => 'PHYSICAL',
                        'AC:L' => 'LOW',
                        'AC:H' => 'HIGH',
                        'PR:N' => 'NONE',
                        'PR:L' => 'LOW',
                        'PR:H' => 'HIGH',
                        'UI:N' => 'NONE',
                        'UI:R' => 'REQUIRED',
                        'S:U' => 'UNCHANGED',
                        'S:C' => 'CHANGED',
                        'C:H' => 'HIGH',
                        'C:L' => 'LOW',
                        'C:N' => 'NONE',
                        'I:H' => 'HIGH',
                        'I:L' => 'LOW',
                        'I:N' => 'NONE',
                        'A:H' => 'HIGH',
                        'A:L' => 'LOW',
                        'A:N' => 'NONE',
                        'Null' => 'Null' }
    metrics_map_v31[code]
  end

  def self.set_scoring_vector(cve_item, rh_vector_string)
    cvss_metrics = rh_vector_string.split(/\//)
    av = cvss_metrics.grep(/^AV:/).first || 'Null'
    ac = cvss_metrics.grep(/^AC:/).first || 'Null'
    pr = cvss_metrics.grep(/^PR:/).first || 'Null'
    ui = cvss_metrics.grep(/^UI:/).first || 'Null'
    scope = cvss_metrics.grep(/^S:/).first || 'Null'
    ci = cvss_metrics.grep(/^C:/).first || 'Null'
    ii = cvss_metrics.grep(/^I:/).first || 'Null'
    ai = cvss_metrics.grep(/^A:/).first || 'Null'
    version = cvss_metrics.grep(/^CVSS:/).first.split(/:/)[1] || 'Null'

    cve_item['impact']['metric']['cvss']['vectorString'] = rh_vector_string || 'Null'
    cve_item['impact']['metric']['cvss']['attackVector'] = metrics_map(av)
    cve_item['impact']['metric']['cvss']['attackComplexity'] = metrics_map(ac)
    cve_item['impact']['metric']['cvss']['privilegesRequired'] = metrics_map(pr)
    cve_item['impact']['metric']['cvss']['userInteraction'] = metrics_map(ui)
    cve_item['impact']['metric']['cvss']['scope'] = metrics_map(scope)
    cve_item['impact']['metric']['cvss']['confidentialityImpact'] = metrics_map(ci)
    cve_item['impact']['metric']['cvss']['integrityImpact'] = metrics_map(ii)
    cve_item['impact']['metric']['cvss']['availabilityImpact'] = metrics_map(ai)
    cve_item['impact']['metric']['cvss']['version'] = version

    cve_item
  end
end
