package mudybluez

import "log"

func Run(pcapNGPath string, tls bool) {
	err := replay(pcapNGPath, tls)
	if err != nil {
		log.Printf("[ERROR] %s", err)
	}
}
