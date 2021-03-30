package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ardanlabs/service/app/sales-api/handlers"
	"github.com/ardanlabs/service/business/data/tests"
)

// UserTests holds methods for each user subtest. This type allows passing
// dependencies for tests while still providing a convenient syntax when
// subtests are registered.
type UserTests struct {
	app        http.Handler
	kid        string
	userToken  string
	adminToken string
}

// TestUsers is the entry point for testing user management functions.
func TestUsers(t *testing.T) {
	test := tests.NewIntegration(
		t,
		tests.DBContainer{
			Image: "postgres:13-alpine",
			Port:  "5432",
			Args:  []string{"-e", "POSTGRES_PASSWORD=postgres"},
		},
	)
	t.Cleanup(test.Teardown)

	shutdown := make(chan os.Signal, 1)
	tests := UserTests{
		app:        handlers.API("develop", shutdown, test.Log, test.Auth, test.DB),
		kid:        test.KID,
		userToken:  test.Token("user@example.com", "gophers"),
		adminToken: test.Token("admin@example.com", "gophers"),
	}

	t.Run("getToken200", tests.getToken200)
}

func (ut *UserTests) getToken200(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/users/token/"+ut.kid, nil)
	w := httptest.NewRecorder()

	r.SetBasicAuth("admin@example.com", "gophers")
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to issues tokens to known users.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen fetching a token with valid credentials.", testID)
		{
			if w.Code != http.StatusOK {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 200 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 200 for the response.", tests.Success, testID)

			var got struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to unmarshal the response : %v", tests.Failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to unmarshal the response.", tests.Success, testID)

			// TODO(jlw) Should we ensure the token is valid?
		}
	}
}
