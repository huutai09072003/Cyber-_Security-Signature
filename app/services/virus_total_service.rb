# app/services/virus_total_service.rb
require "httparty"
require "zip" # Sử dụng gem 'rubyzip'

class VirusTotalService
  include HTTParty
  base_uri "https://www.virustotal.com/api/v3"

  def initialize(api_key)
    @headers = { "x-apikey" => api_key }
  end

  # Giải nén file .zip và quét từng file
  def scan_zip_file(file_path)
    results = []

    # Giải nén và quét từng file
    Zip::File.open(file_path) do |zip_file|
      zip_file.each do |entry|
        next unless entry.file?

        # Lưu tạm file và quét
        temp_file = Tempfile.new(entry.name)
        entry.extract(temp_file.path) { true }
        results << upload_and_scan_file(temp_file.path)
        temp_file.close
      end
    end

    results
  end

  private

  # Quét một file đơn lẻ
  def upload_and_scan_file(file_path)
    file = File.open(file_path, "rb")
    response = self.class.post("/files", headers: @headers.merge({ "Content-Type" => "multipart/form-data" }), body: { file: file })
    parse_response(response)
  ensure
    file.close if file
  end

  def parse_response(response)
    if response.success?
      data = response.parsed_response["data"]
      { scan_id: data["id"], status: "uploaded successfully" }
    else
      { error: "Error: #{response.code}, Message: #{response.message}" }
    end
  end
end
