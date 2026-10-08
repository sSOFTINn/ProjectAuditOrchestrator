package fixture

import "crypto/tls"

var insecure = tls.Config{InsecureSkipVerify: true}
