package viewer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionClaimHeader = "X-Qodo-Viewer-Session"
	sessionCookieName  = "qodo_viewer_session"
)

var errRetireViewerLauncher = errors.New("could not retire viewer launcher")

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
		if status == http.StatusTooManyRequests {
			writer.Header().Set("Retry-After", "1")
		}
		http.Error(writer, sessionClaimErrorMessage(err), status)
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
		if status == http.StatusTooManyRequests {
			writer.Header().Set("Retry-After", "1")
		}
		http.Error(writer, sessionClaimErrorMessage(err), status)
		return
	}
	setSessionCookie(writer, token)
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (application *handler) claimSession(token string) (int, error) {
	application.sessionMutex.Lock()
	defer application.sessionMutex.Unlock()
	now := time.Now()
	decodedToken, err := hex.DecodeString(token)
	if err != nil || len(decodedToken) != 32 {
		if now.Before(application.nextClaimAt) {
			return http.StatusTooManyRequests, errors.New("viewer session claims are rate limited")
		}
		application.recordClaimFailure(now)
		return http.StatusBadRequest, errors.New("a valid session claim is required")
	}
	providedDigest := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(
		providedDigest[:],
		application.expectedClaimDigest[:],
	) != 1 {
		if now.Before(application.nextClaimAt) {
			return http.StatusTooManyRequests, errors.New("viewer session claims are rate limited")
		}
		application.recordClaimFailure(now)
		return http.StatusForbidden, errors.New("invalid viewer session claim")
	}
	if application.sessionToken != "" {
		return http.StatusNoContent, nil
	}
	if application.claimCleanup != nil {
		if err := application.claimCleanup(); err != nil {
			return http.StatusInternalServerError, fmt.Errorf(
				"%w: %w",
				errRetireViewerLauncher,
				err,
			)
		}
	}
	application.claimFailures = 0
	application.nextClaimAt = time.Time{}
	application.sessionToken = token
	return http.StatusNoContent, nil
}

func sessionClaimErrorMessage(err error) string {
	if errors.Is(err, errRetireViewerLauncher) {
		return errRetireViewerLauncher.Error()
	}
	return err.Error()
}

func (application *handler) recordClaimFailure(now time.Time) {
	application.claimFailures++
	if application.claimFailures >= 5 {
		application.claimFailures = 0
		application.nextClaimAt = now.Add(time.Second)
	}
}

func setSessionCookie(writer http.ResponseWriter, token string) {
	// The viewer is loopback-only HTTP; Secure would make the browser drop the
	// cookie, while self-signed local TLS would not add an authenticated peer.
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
