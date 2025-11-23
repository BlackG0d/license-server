
function getVerificationEmailHtml(code) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>MyPasSwordX Verification Code</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    /* General resets */
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
    }
    img {
      border: 0;
      outline: none;
      text-decoration: none;
      -ms-interpolation-mode: bicubic;
      display: block;
    }
    table {
      border-collapse: collapse;
      border-spacing: 0;
    }
    td {
      padding: 0;
      vertical-align: top;
    }

    /* Responsive styles */
    @media screen and (max-width: 600px) {
      .container {
        width: 100% !important;
        max-width: 100% !important;
        border-radius: 0 !important;
      }
      .inner-padding {
        padding-left: 16px !important;
        padding-right: 16px !important;
      }
      .logo-wrapper {
        width: 72px !important;
        height: 72px !important;
      }
      .code-box {
        width: 100% !important;
      }
      .code-text {
        font-size: 24px !important;
        letter-spacing: 0.22em !important;
      }
    }

    @media screen and (max-width: 400px) {
      .inner-padding {
        padding-left: 12px !important;
        padding-right: 12px !important;
      }
      h1 {
        font-size: 22px !important;
      }
      .subtitle {
        font-size: 12px !important;
        letter-spacing: 0.16em !important;
      }
      .body-text {
        font-size: 14px !important;
      }
      .meta-text {
        font-size: 11px !important;
      }
    }
  </style>
</head>
<body style="
  margin:0;
  padding:0;
  background:#f2f3f7;
  background-image: radial-gradient(circle at 0 0, #ffffff 0, #f2f3f7 40%, #e6e9f0 100%);
  font-family:-apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;
  color:#141414;
">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <!-- Card -->
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="container" style="
          max-width:480px;
          background:rgba(255,255,255,0.80);
          border-radius:24px;
          border:1px solid rgba(255,255,255,0.65);
          box-shadow:0 18px 45px rgba(0,0,0,0.08);
          backdrop-filter:blur(18px);
        ">
          <tr>
            <td align="center" class="inner-padding" style="padding:32px 32px 12px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" 
       width="88" height="88" style="
  border-radius:50%;
  background:linear-gradient(135deg,#ff7a1a,#ff4a1a);
  box-shadow:0 12px 25px rgba(0,0,0,0.18);
  margin-bottom:16px;
">
<tr>
    <td height="20"></td>
  </tr>
  <tr>
    <td align="center" valign="middle">
      <img src="https://nahapetfx.com/images/logo.png"
           alt=""
           width="73"
           style="display:block; border:0; outline:none; height:auto;" />
    </td>
  </tr>
</table>

              <h1 style="
                margin:0;
                margin-bottom:4px;
                font-size:26px;
                font-weight:700;
                letter-spacing:0.02em;
                color:#ff6a1a;
              ">MyPasSwordX</h1>

              <div class="subtitle" style="
                font-size:14px;
                letter-spacing:0.18em;
                text-transform:uppercase;
                color:#ff6a1a;
                margin-bottom:12px;
              ">
                Verification Code
              </div>

              <p class="body-text" style="
                margin:0;
                margin-bottom:24px;
                font-size:15px;
                line-height:1.5;
                color:#555555;
              ">
                Use this code to verify your NahapetFX account
                and continue working in the <strong>MyPasSwordX</strong> app.
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" class="inner-padding" style="padding:0 32px 24px;">
              <div class="code-box" style="
                display:inline-block;
                padding:16px 32px;
                border-radius:18px;
                background:rgba(255,255,255,0.95);
                border:1px solid rgba(255,255,255,0.9);
                box-shadow:0 10px 30px rgba(0,0,0,0.08);
              ">
                <span style="
                  font-size:13px;
                  text-transform:uppercase;
                  letter-spacing:0.18em;
                  color:#999999;
                  display:block;
                  margin-bottom:4px;
                ">
                  Your Code
                </span>
                <span class="code-text" style="
                  font-size:28px;
                  font-weight:700;
                  letter-spacing:0.28em;
                  color:#ff6a1a;
                  padding-left:0.28em;
                  display:inline-block;
                ">
                  ${code}
                </span>
              </div>
            </td>
          </tr>

          <tr>
            <td align="center" class="inner-padding" style="padding:0 32px 24px;">
              <p class="meta-text" style="
                margin:0;
                font-size:13px;
                line-height:1.6;
                color:#888888;
              ">
                The code is valid for
                <strong>15 minutes</strong> and can only be used once.
                If you did not request this code, simply ignore this email.
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" class="inner-padding" style="
              padding:0 24px 24px;
              border-top:1px solid rgba(255,255,255,0.7);
            ">
              <p style="
                margin:16px 0 4px;
                font-size:12px;
                color:#b0b0b0;
              ">
                With love for magic and technology,<br/>
                the <strong>NahapetFX</strong> team
              </p>
              <p style="
                margin:0 0 8px;
                font-size:11px;
                color:#c0c0c0;
              ">
                This is an automated email, please do not reply.
              </p>
              <p style="
                margin:0 0 4px;
                font-size:11px;
                color:#c0c0c0;
              ">
                © NahapetFX. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
        <!-- /Card -->
      </td>
    </tr>
  </table>
</body>
</html>`;
}

module.exports = {
  getVerificationEmailHtml,
};
