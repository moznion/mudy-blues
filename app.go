package mudybluez

import "log"

func Run(pcapNGPath string, tls bool) {
	log.Println(replay(pcapNGPath, tls))
}
