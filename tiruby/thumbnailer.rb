module Thumbnailer
	def self.ignore_max
		128
	end

	def self.thumb_size
		96
	end


	def self.direct_generate(src)
		require 'RMagick'

		img = Magick::Image.from_blob(src).pop
		imax = self.ignore_max
		thsz = self.thumb_size

		iw = img.columns
		ih = img.rows
		if iw > imax || ih > imax
			rt = 1.0

			if (iw > ih)
				rt = thsz.to_f / iw.to_f
				img.resize!(thsz, ih.to_f * rt)
			else
				rt = thsz.to_f / ih.to_f
				img.resize!(iw.to_f * rt, thsz)
			end			
		end

		return img.to_blob
	end
end


if __FILE__ == $0
	require 'rubygems'
	# test
	File.open("../../../cobayahika.png", "rb") {|f|
		resb = Thumbnailer.direct_generate(f.read)
		File.open("../../../thumtest-result.png", "wb") {|wf|
			wf.write(resb)
		}
	}
end
