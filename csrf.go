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

func GetToken(w http.ResponseWriter, r *http.Request) string {

  gob.Register(Tokens{})

  // Number of random bytes to generate
  n := 500
	b := make([]byte, n)

  // Read in from random
	_, err := rand.Read(b)

  // Check error
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}

  // Generate sha512 hash
  hash := sha512.New()
  hash.Write(b)

  token := hex.EncodeToString(hash.Sum(nil))

  session, _ := sessionStore.Get(r, "token")

  session.Options = &sessions.Options{
      Path:     "/",
      MaxAge:   60 * 60 * 2,
      HttpOnly: true,
  }

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


func CheckToken(w http.ResponseWriter, r *http.Request) bool {
  session, _ := sessionStore.Get(r, "token")

  session.Options = &sessions.Options{
      Path:     "/",
      MaxAge:   60 * 60 * 2,
      HttpOnly: true,
  }
  if session.Values["tokens"] != nil {
    t := session.Values["tokens"].(Tokens)

    for _, tok := range t.T {
      fmt.Print(int64(time.Since(tok.Created)) > int64(math.Pow(10, 9) * 60 * 20))
    }
    return true
  }
  return false
}
