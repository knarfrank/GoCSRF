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

var sessionStore = sessions.NewCookieStore([]byte("a1c72f9a30f2111c59fb331f07517211a730b3fdc7d9cc77a5c698043caefb7f9ff18039dec03935838ccd1a7985cefe48e3c14043d4ca2"))

type Token struct {
  Hash string
  Created time.Time
}

type Tokens struct {
  T []Token
}


/*
  Generates a random token
*/
func GetToken(w http.ResponseWriter, r *http.Request) string {
  gob.Register(Tokens{})

  session := getSession(w, r)
  token := randomHash()
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
    fmt.Println(len(t.T))
    for id, tok := range t.T {
      // Removed tokens that are older than 30 minutes
      if int64(time.Since(tok.Created)) > int64(math.Pow(10, 9) * 60 * 30) {
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
  t.T[id] = t.T[len(t.T)-1]
  t.T = t.T[0:len(t.T)-1]
  session.Values["tokens"] = t
  session.Save(r, w)
}

/*
  Returns a random hash
*/
func randomHash() string {
  // Number of random bytes to generate
  n := 500
  b := make([]byte, n)

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
  session, _ := sessionStore.Get(r, "token")
  session.Options = &sessions.Options{
      Path:     "/",
      MaxAge:   60 * 60 * 2,
      HttpOnly: true,
  }
  return session
}
