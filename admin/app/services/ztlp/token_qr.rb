# frozen_string_literal: true

require "rqrcode"

module Ztlp
  # Renders an enrollment token URI as an inline SVG QR code.
  #
  # Inline <svg> (not an <img> pointing at a data: URI) because the panel CSP is
  # `img-src 'self' 'data'` — a data: URI would technically be allowed, but an
  # inline SVG has zero external references and is CSP-clean by construction.
  # The SVG is produced by rqrcode from the (already validated) token string,
  # so no server data is interpolated into markup by hand.
  class TokenQr
    SVG_SIZE = 160
    MODULE_SIZE = 4

    # Return an HTML-safe inline <svg> for the given token string.
    def self.svg(token_uri)
      qr = RQRCode::QRCode.new(token_uri.to_s)
      qr.as_svg(size: SVG_SIZE, module_size: MODULE_SIZE)
    end
  end
end
