# A Concern to pull EPSS data based on a list of CVEs
#  - Written by Michael Gargiullo (mgargiullo@gmail.com)
# 
# Stripped to allow customization

require 'rest-client'

module Dradis::Pro::Plugins::Mgargiullo::Epss
  extend ActiveSupport::Concern

  def self.get_epss_data(cve:)
    # Pulling from https://api.first.org/epss/
    api_url = 'https://api.first.org/epss/'

    # Clean up CVE: Dradis stored as list-like, but as text
    cve_id_array = []
    cve.split(',').each do |single_cve|
      cve_id_array.append(single_cve.strip.upcase)
    end

    # Build param data: Make it an array
    cve_params = cve_id_array.join(',')

    # Fetch EPSS data: Send CVE(s), get JSON
    response = RestClient.get api_url, {params: {cve: cve_params}}, {accept: :json}

    # check response
    if response.code == 200
      # Sample Response Schema
      # {
      #     "status": "OK",
      #     "status-code": 200,
      #     "version": "1.0",
      #     "access": "private, no-cache",
      #     "total": 2,
      #     "offset": 0,
      #     "limit": 100,
      #     "data": [
      #         {
      #             "cve": "CVE-2021-40438",
      #             "epss": "0.972240000",
      #             "percentile": "1.000000000",
      #             "date": "2022-02-28"
      #         },
      #         {
      #             "cve": "CVE-2019-16759",
      #             "epss": "0.968170000",
      #             "percentile": "0.999990000",
      #             "date": "2022-02-28"
      #         }
      #     ]
      # }
    end
  end
end
