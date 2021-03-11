package handlers

import (
	"context"
	"errors"
	"math/rand"
	"net/http"

	"github.com/ardanlabs/service/business/validate"
	"github.com/ardanlabs/service/foundation/web"
)

func readiness(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if n := rand.Intn(100); n%2 == 0 {
		return validate.NewRequestError(errors.New("trusted error"), http.StatusBadRequest)
	}

	status := struct {
		Status string
	}{
		Status: "OK",
	}
	return web.Respond(ctx, w, status, http.StatusOK)
}
