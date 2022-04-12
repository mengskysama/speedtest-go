package web

import (
	"fmt"
	"github.com/dchest/captcha"
	"github.com/librespeed/speedtest/config"
	"github.com/librespeed/speedtest/iputils"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	tokenStore      = make(map[int64]struct{})
	tokenStoreMutex = sync.Mutex{}
	storeTokenMutex = sync.Mutex{}
	CaptchaLen      = 3
)

func genCaptcha(w http.ResponseWriter, r *http.Request) {
	conf := config.LoadedConfig()
	if conf.EnableCaptcha == false {
		http.Error(w, "captcha disabled", http.StatusNotFound)
		return
	}

	id := captcha.NewLen(CaptchaLen)
	ck := http.Cookie{
		Name:    "captcha",
		Domain:  "",
		Path:    "/",
		Expires: time.Now().Add(time.Minute * 10),
		Value:   id,
	}
	http.SetCookie(w, &ck)
	_ = captcha.WriteImage(w, id, 128, 35)
}

func CheckToken(r *http.Request) bool {
	conf := config.LoadedConfig()
	if conf.EnableCaptcha == false {
		return true
	}

	cc, err := r.Cookie("token")
	if err != nil {
		return false
	}

	v, err := strconv.ParseInt(cc.Value, 10, 64)
	if err != nil {
		return false
	}

	tokenStoreMutex.Lock()
	_, ok := tokenStore[v]
	tokenStoreMutex.Unlock()
	return ok
}

func lenToken() (l int) {
	tokenStoreMutex.Lock()
	l = len(tokenStore)
	tokenStoreMutex.Unlock()
	return
}

func storeToken(token int64) {
	tokenStoreMutex.Lock()
	tokenStore[token] = struct{}{}
	tokenStoreMutex.Unlock()
}

func cleanupTokenWorker() {
	for {
		time.Sleep(time.Second)
		ts := time.Now().UnixNano()
		tokenStoreMutex.Lock()
		for k := range tokenStore {
			if k < ts {
				delete(tokenStore, k)
			}
		}
		tokenStoreMutex.Unlock()
	}
}

func getToken(w http.ResponseWriter, r *http.Request) {
	cfg := config.LoadedConfig()

	ip := iputils.GetClientIP(r)
	if iputils.IsLimited(ip) {
		http.Error(w, "Your ip "+ip+" out of daily traffic limited", http.StatusForbidden)
		return
	}
	if cfg.EnableCaptcha == false {
		return
	}

	storeTokenMutex.Lock()
	defer storeTokenMutex.Unlock()

	cc, err := r.Cookie("captcha")
	if err != nil {
		http.Error(w, "captcha cookie not found", http.StatusForbidden)
		return
	}

	if cfg.InflightTestLimit > 0 && int64(lenToken()) >= cfg.InflightTestLimit {
		http.Error(w, "Too many inflight test, try again later", http.StatusTooManyRequests)
		return
	}

	solution := r.URL.Query().Get("solution")
	if !captcha.VerifyString(cc.Value, solution) {
		http.Error(w, "bad solution", http.StatusForbidden)
		return
	}

	d, _ := time.ParseDuration(cfg.TokenTTLDuration)
	ts := time.Now().Add(d).UnixNano()
	storeToken(ts)

	expires := time.Now().Add(time.Hour)
	ck := http.Cookie{
		Name:    "token",
		Domain:  "",
		Path:    "/",
		Expires: expires,
	}
	ck.Value = fmt.Sprint(ts)
	http.SetCookie(w, &ck)
}

func init() {
	go cleanupTokenWorker()
}
