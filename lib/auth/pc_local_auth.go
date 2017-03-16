package auth

import (
    "encoding/json"

    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/trace"

    "github.com/gokyle/hotp"
)

// TODO : apply encryption
func RequestHOTPforSignupToken(client *TunClient, signupToken string) ([]string, error) {
    // User will scan QRcode, here we just loads the OTP generator
    // right from the backend.
    // TODO : we need encryption
    out, err := client.PostJSON(apiEndpoint(PocketUserSignup, PocketSignupToken),
        signupTokenReq{
            SignupToken: signupToken,
        })
    if err != nil {
        return nil, trace.Wrap(err)
    }
    var tokenPack signupTokenPack
    if err := json.Unmarshal(out.Bytes(), &tokenPack); err != nil {
        return nil, trace.Wrap(err)
    }
    otp, err := hotp.Unmarshal(tokenPack.SignupToken.Hotp)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    hotpTokens := make([]string, defaults.HOTPFirstTokensRange)
    for i := 0; i < defaults.HOTPFirstTokensRange; i++ {
        hotpTokens[i] = otp.OTP()
    }
    return hotpTokens, nil
}