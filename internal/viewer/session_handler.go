package viewer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const (
	sessionClaimHeader = "X-Qodo-Viewer-Session"
	sessionCookieName  = "qodo_viewer_session"
)

func (application *handler) authorized(request *http.Request) bool {
	const bearerPrefix = "Bearer "
	authorization := request.Header.Get("Authorization")
	providedToken := ""
	if strings.HasPrefix(authorization, bearerPrefix) {
		providedToken = strings.TrimPrefix(authorization, bearerPrefix)
	}
	if providedToken == "" {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil {
			return false
		}
		providedToken = cookie.Value
	}
	providedDigest := sha256.Sum256([]byte(providedToken))
	application.sessionMutex.RLock()
	expectedToken := application.sessionToken
	application.sessionMutex.RUnlock()
	if expectedToken == "" {
		return false
	}
	expectedDigest := sha256.Sum256([]byte(expectedToken))
	return subtle.ConstantTimeCompare(
		providedDigest[:],
		expectedDigest[:],
	) == 1
}

func (application *handler) handleSession(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := request.Header.Get(sessionClaimHeader)
	status, err := application.claimSession(token)
	if err != nil {
		http.Error(writer, err.Error(), status)
		return
	}
	setSessionCookie(writer, token)
	writer.WriteHeader(http.StatusNoContent)
}

func (application *handler) handleSessionBootstrap(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1024)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "A valid session claim is required", http.StatusBadRequest)
		return
	}
	token := request.PostForm.Get("session")
	status, err := application.claimSession(token)
	if err != nil {
		http.Error(writer, err.Error(), status)
		return
	}
	setSessionCookie(writer, token)
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (application *handler) claimSession(token string) (int, error) {
	decodedToken, err := hex.DecodeString(token)
	if err != nil || len(decodedToken) != 32 {
		return http.StatusBadRequest, errors.New("a valid session claim is required")
	}
	providedDigest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(
		providedDigest[:],
		application.expectedClaimDigest[:],
	) != 1 {
		return http.StatusForbidden, errors.New("invalid viewer session claim")
	}
	application.sessionMutex.Lock()
	defer application.sessionMutex.Unlock()
	if application.sessionToken != "" {
		return http.StatusNoContent, nil
	}
	if application.claimCleanup != nil {
		if err := application.claimCleanup(); err != nil {
			return http.StatusInternalServerError, errors.New(
				"could not retire viewer launcher",
			)
		}
	}
	application.sessionToken = token
	return http.StatusNoContent, nil
}

func setSessionCookie(writer http.ResponseWriter, token string) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
