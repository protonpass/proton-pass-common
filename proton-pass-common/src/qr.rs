use qrcode::QrResult;
use qrcode::render::svg;

pub fn generate_svg_qr_code(value: &str) -> QrResult<String> {
    let code = qrcode::QrCode::new(value)?;
    let svg = code.render::<svg::Color>().build();
    Ok(svg)
}
