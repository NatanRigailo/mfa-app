package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp/totp"
)

const registerPath = "/register"

type PageData struct {
	AppName   string
	CSRFToken string
	Flashes   []Flash
	EditMode  bool
	Groups    []LetterGroup
}

type LetterGroup struct {
	Letter string
	Tokens []Token
}

// pageData is called by GET handlers: reads session and pops flashes for rendering.
func (a *App) pageData(r *http.Request) (Session, PageData) {
	sess := getSession(r, a.cfg.SecretKey)
	return sess, PageData{
		AppName:   a.cfg.AppName,
		CSRFToken: sess.CSRFToken,
		Flashes:   sess.popFlashes(),
		EditMode:  sess.EditMode,
	}
}

func groupTokens(tokens []Token) []LetterGroup {
	index := map[string]*LetterGroup{}
	var letters []string

	for _, t := range tokens {
		runes := []rune(t.Name)
		if len(runes) == 0 {
			continue
		}
		letter := strings.ToUpper(string(runes[0]))
		if _, ok := index[letter]; !ok {
			index[letter] = &LetterGroup{Letter: letter}
			letters = append(letters, letter)
		}
		index[letter].Tokens = append(index[letter].Tokens, t)
	}

	sort.Strings(letters)
	groups := make([]LetterGroup, len(letters))
	for i, l := range letters {
		groups[i] = *index[l]
	}
	return groups
}

func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := a.db.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "db": err.Error()}) //nolint:errcheck,gosec
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "db": "ok"}) //nolint:errcheck,gosec
}

func (a *App) getNewCodes(w http.ResponseWriter, r *http.Request) {
	if tok := a.cfg.APIToken; tok != "" {
		auth := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+tok)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	tokens, err := a.db.activeTokens()
	if err != nil {
		slog.Error("get_new_codes: db error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	codes := make(map[string]string, len(tokens))
	now := time.Now()
	for _, t := range tokens {
		code, err := totp.GenerateCode(t.Secret, now)
		if err != nil {
			slog.Error("totp generate error", "name", t.Name, "err", err)
			continue
		}
		codes[t.Name] = code
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"codes": codes}) //nolint:errcheck,gosec
}

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	sess, data := a.pageData(r)

	var tokens []Token
	var err error
	if sess.EditMode {
		tokens, err = a.db.allTokens()
	} else {
		tokens, err = a.db.activeTokens()
	}
	if err != nil {
		slog.Error("index: db error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data.Groups = groupTokens(tokens)
	saveSession(w, a.cfg.SecretKey, sess)
	a.render(w, "index", data)
}

func (a *App) indexPost(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r, a.cfg.SecretKey)

	redirect := func(category, msg string) {
		sess.addFlash(category, msg)
		saveSession(w, a.cfg.SecretKey, sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	if !sess.EditMode {
		redirect("error", "Modo de edição não está ativo.")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !sess.validCSRF(r.FormValue("csrf_token")) {
		redirect("error", "Token de segurança inválido. Recarregue a página e tente novamente.")
		return
	}

	tokens, err := a.db.allTokens()
	if err != nil {
		slog.Error("indexPost: db error", "err", err)
		redirect("error", "Erro ao carregar tokens.")
		return
	}

	var updates []TokenUpdate
	for _, t := range tokens {
		newName := strings.TrimSpace(r.FormValue(fmt.Sprintf("name_%d", t.ID)))
		if newName == "" {
			continue
		}
		active := r.FormValue(fmt.Sprintf("ativo_%d", t.ID)) == "on"

		if exists, err := a.db.nameExistsExcept(newName, t.ID); err != nil {
			slog.Error("indexPost: name check error", "err", err)
			redirect("error", "Erro ao verificar nome.")
			return
		} else if exists {
			redirect("error", fmt.Sprintf("Nome '%s' já está em uso.", newName))
			return
		}
		updates = append(updates, TokenUpdate{ID: t.ID, Name: newName, Active: active})
	}

	if err := a.db.updateTokens(updates); err != nil {
		slog.Error("indexPost: update error", "err", err)
		redirect("error", "Erro ao salvar alterações.")
		return
	}

	redirect("success", "Alterações salvas!")
}

func (a *App) toggleEdit(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r, a.cfg.SecretKey)

	redirect := func(category, msg string) {
		sess.addFlash(category, msg)
		saveSession(w, a.cfg.SecretKey, sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !sess.validCSRF(r.FormValue("csrf_token")) {
		redirect("error", "Token de segurança inválido.")
		return
	}

	if sess.EditMode {
		sess.EditMode = false
		redirect("info", "Modo de edição desativado.")
		return
	}

	palavra := strings.TrimSpace(r.FormValue("palavra"))
	editPass := a.cfg.EditPass
	if editPass == "" || subtle.ConstantTimeCompare([]byte(palavra), []byte(editPass)) == 1 {
		sess.EditMode = true
		redirect("success", "Modo de edição ativado!")
	} else {
		redirect("error", "Senha incorreta.")
	}
}

func (a *App) deleteToken(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r, a.cfg.SecretKey)

	redirect := func(category, msg string) {
		sess.addFlash(category, msg)
		saveSession(w, a.cfg.SecretKey, sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	if !sess.EditMode {
		redirect("error", "Acesso negado.")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !sess.validCSRF(r.FormValue("csrf_token")) {
		redirect("error", "Token de segurança inválido.")
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token, err := a.db.getToken(id)
	if err != nil {
		slog.Error("delete: db error", "err", err)
		redirect("error", "Erro ao buscar token.")
		return
	}
	if token == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := a.db.deleteToken(id); err != nil {
		slog.Error("delete: db error", "id", id, "err", err)
		redirect("error", "Erro ao remover token.")
		return
	}
	redirect("success", fmt.Sprintf("Token '%s' removido.", token.Name))
}

func (a *App) registerGet(w http.ResponseWriter, r *http.Request) {
	sess, data := a.pageData(r)
	saveSession(w, a.cfg.SecretKey, sess)
	if !a.cfg.RegisterAble {
		a.render(w, "register_disabled", data)
		return
	}
	a.render(w, "register", data)
}

func (a *App) registerPost(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.RegisterAble {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sess := getSession(r, a.cfg.SecretKey)

	redirect := func(dest, category, msg string) {
		sess.addFlash(category, msg)
		saveSession(w, a.cfg.SecretKey, sess)
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}

	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxUploadMB*1024*1024)
	if err := r.ParseMultipartForm(a.cfg.MaxUploadMB * 1024 * 1024); err != nil { //nolint:gosec
		redirect(registerPath, "error", "Erro ao processar formulário.")
		return
	}
	if !sess.validCSRF(r.FormValue("csrf_token")) {
		redirect(registerPath, "error", "Token de segurança inválido.")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	secret, errMsg := resolveSecret(r)
	if errMsg != "" {
		redirect(registerPath, "error", errMsg)
		return
	}

	if name == "" || secret == "" {
		redirect(registerPath, "error", "Nome e secret são obrigatórios.")
		return
	}

	if existing, err := a.db.tokenByName(name); err != nil {
		slog.Error("register: db error", "err", err)
		redirect(registerPath, "error", "Erro interno.")
		return
	} else if existing != nil {
		redirect(registerPath, "error", fmt.Sprintf("Já existe um token com o nome '%s'.", name))
		return
	}

	if err := a.db.createToken(name, secret); err != nil {
		slog.Error("register: create error", "name", name, "err", err)
		redirect(registerPath, "error", "Erro ao salvar o token.")
		return
	}
	redirect("/", "success", "Token registrado com sucesso!")
}

func resolveSecret(r *http.Request) (secret, errMsg string) {
	if raw := strings.TrimSpace(r.FormValue("secret")); raw != "" {
		if s := sanitizeSecret(raw); s != "" {
			return s, ""
		}
		return "", "Secret inválido. Verifique a chave Base32."
	}

	file, _, err := r.FormFile("qr_code")
	if err != nil {
		return "", ""
	}
	defer file.Close() //nolint:errcheck

	img, _, err := image.Decode(file)
	if err != nil {
		return "", "Não foi possível decodificar a imagem."
	}
	uri, err := decodeQR(img)
	if err != nil {
		return "", "Não foi possível decodificar o QR Code."
	}
	raw := extractSecretFromURI(uri)
	if raw == "" {
		return "", "QR Code não contém um URI otpauth://totp/ válido."
	}
	if s := sanitizeSecret(raw); s != "" {
		return s, ""
	}
	return "", "Secret extraído do QR Code é inválido."
}

func sanitizeSecret(secret string) string {
	cleaned := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if _, err := totp.GenerateCode(cleaned, time.Now()); err != nil {
		return ""
	}
	return cleaned
}

func decodeQR(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", err
	}
	return result.GetText(), nil
}

func extractSecretFromURI(uri string) string {
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		return ""
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return parsed.Query().Get("secret")
}
