package web

import (
	"crypto/rand"
	"fmt"
	"github.com/librespeed/speedtest/config"
	"github.com/librespeed/speedtest/iputils"
	log "github.com/sirupsen/logrus"
	"github.com/umahmood/haversine"
	"strconv"
	"strings"
)

var (
	serverCoord haversine.Coord
)

func getRandomData(length int) []byte {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		log.Fatalf("Failed to generate random data: %s", err)
	}
	return data
}

func SetServerLocation(conf *config.Config) {
	if conf.ServerLat != 0 || conf.ServerLng != 0 {
		log.Infof("Configured server coordinates: %.6f, %.6f", conf.ServerLat, conf.ServerLng)
		serverCoord.Lat = conf.ServerLat
		serverCoord.Lon = conf.ServerLng
		return
	}

	var err error
	r := iputils.GetIPInfo("")
	serverCoord, err = parseLocationString(r.Location)
	if err != nil {
		log.Errorf("Cannot get server coordinates: %s", err)
		return
	}

	log.Infof("Fetched server coordinates: %.6f, %.6f", serverCoord.Lat, serverCoord.Lon)
}

func parseLocationString(location string) (haversine.Coord, error) {
	var coord haversine.Coord

	parts := strings.Split(location, ",")
	if len(parts) != 2 {
		err := fmt.Errorf("unknown location format: %s", location)
		log.Error(err)
		return coord, err
	}

	lat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		log.Errorf("Error parsing latitude: %s", parts[0])
		return coord, err
	}

	lng, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		log.Errorf("Error parsing longitude: %s", parts[0])
		return coord, err
	}

	coord.Lat = lat
	coord.Lon = lng

	return coord, nil
}

func calculateDistance(clientLocation string, unit string) string {
	clientCoord, err := parseLocationString(clientLocation)
	if err != nil {
		log.Errorf("Error parsing client coordinates: %s", err)
		return ""
	}

	dist, km := haversine.Distance(clientCoord, serverCoord)
	unitString := " mi"

	switch unit {
	case "km":
		dist = km
		unitString = " km"
	case "NM":
		dist = km * 0.539957
		unitString = " NM"
	}

	return fmt.Sprintf("%.2f%s", dist, unitString)
}
