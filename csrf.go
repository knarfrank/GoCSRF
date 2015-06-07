package csrf


import (
  "fmt"
  "net/http"
  "time"
  "encoding/gob"
  "github.com/gorilla/sessions"
  "crypto/sha512"
  "encoding/hex"
	"crypto/rand"
  "math"
)



type Token struct {
  Hash string
  Created time.Time
}

type Tokens struct {
  T []Token
}

type Config struct {
  sessionName string
  maxAge int
  entropy int
}

var sessionStore *sessions.FilesystemStore
var config Config


func Init(sessionName string, maxAge int) {
  // Initialise with a random key
  sessionStore = sessions.NewFilesystemStore("", []byte(RandomHash()))
  config.sessionName = sessionName
  config.maxAge = maxAge
  config.entropy = 500
}


/*
  Generates a random token
*/
func GetToken(w http.ResponseWriter, r *http.Request) string {
  gob.Register(Tokens{})

  session := getSession(w, r)
  token := RandomHash()
  var t Tokens
  if session.Values["tokens"] == nil {
    a := make([]Token, 1)
    a[0] = Token{token, time.Now()}
    t = Tokens{a}
    session.Values["tokens"] = t
  } else {
    t = session.Values["tokens"].(Tokens)
    t.T = append(t.T, Token{token, time.Now()})
    session.Values["tokens"] = t

  }


  session.Save(r, w)


  // Return hex encoded token
  return token
}


/*
  Checks if a token is valid
*/
func CheckToken(w http.ResponseWriter, r *http.Request, requestToken string) bool {
  session := getSession(w, r)

  if session.Values["tokens"] != nil {
    t := session.Values["tokens"].(Tokens)
    for id, tok := range t.T {
      // Removed tokens that are older than 30 minutes
      if int64(time.Since(tok.Created)) > (int64(math.Pow(10, 9)) * int64(config.maxAge)) {
        deleteToken(w, r, id)
      }
      // If there is a match return truw
      if tok.Hash == requestToken {
        deleteToken(w, r, id)
        return true
      }
    }
  }
  return false
}


/*
  Deletes a token from the session (Given a session array id)
*/
func deleteToken(w http.ResponseWriter, r *http.Request, id int) {
  session := getSession(w, r)
  t := session.Values["tokens"].(Tokens)
  if id < len(t.T) && len(t.T) > 0 {
    t.T[id] = t.T[len(t.T)-1]
    t.T = t.T[0:len(t.T)-1]
    session.Values["tokens"] = t
    session.Save(r, w)
  }
}

/*
  Returns a random hash
*/
func RandomHash() string {
  // Generate array of bytes
  b := make([]byte, config.entropy)

  // Read in from random
  _, err := rand.Read(b)

  // Check error
  if err != nil {
    fmt.Println("Error:", err)
    return ""
  }

  // Generate sha512 hash
  hash := sha512.New()
  hash.Write(b)

  return hex.EncodeToString(hash.Sum(nil))
}




/*
  Gets the token session
*/
func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
  session, _ := sessionStore.Get(r, config.sessionName)
  session.Options = &sessions.Options{
      Path:     "/",
      MaxAge:   60 * config.maxAge,
      HttpOnly: true,
  }
  return session
}
