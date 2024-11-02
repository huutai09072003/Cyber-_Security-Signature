# app/services/virus_total_service.rb
require "httparty"
require "digest"

class VirusTotalService
  include HTTParty
  base_uri "https://www.virustotal.com/api/v3"

  def initialize(api_key)
    @headers = {
      "x-apikey" => api_key
    }
  end

  # Phương thức để quét URL
  def scan_url(url)
    response = self.class.post("/urls", headers: @headers, body: { url: url })
    parse_response(response)
  end

  # Phương thức để quét file dựa trên hàm băm SHA256
  def scan_file(file_path)
    file_hash = Digest::SHA256.file(file_path).hexdigest
    response = self.class.get("/files/#{file_hash}", headers: @headers)
    parse_response(response)
  end

  private

  # Phương thức để xử lý kết quả phản hồi
  def parse_response(response)
    if response.success?
      data = response.parsed_response["data"]
      {
        scan_date: data["attributes"]["last_analysis_date"],
        scan_results: data["attributes"]["last_analysis_results"],
        malicious_count: data["attributes"]["last_analysis_stats"]["malicious"]
      }
    else
      { error: "Error: #{response.code}, Message: #{response.message}" }
    end
  end
end
