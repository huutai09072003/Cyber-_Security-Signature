# app/controllers/files_controller.rb
class FilesController < ApplicationController
  def new
  end

  def create
    binding.pry
    file = params[:file]
    if file
      service = VirusTotalService.new(ENV["VIRUSTOTAL_API_KEY"])
      result = service.upload_and_scan_file(file.path)

      if result[:error]
        flash[:alert] = "Lỗi khi quét file: #{result[:error]}"
      else
        flash[:notice] = "File đã được tải lên và quét thành công! ID quét của file: #{result[:scan_id]}"
      end
    else
      flash[:alert] = "Vui lòng chọn một file để quét."
    end
    redirect_to new_file_path
  end
end
