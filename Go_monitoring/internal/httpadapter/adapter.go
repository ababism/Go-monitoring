package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"net/http"
	"time"

	"github.com/anonimpopov/hw4/internal/docs" // go:generate
	"github.com/anonimpopov/hw4/internal/model"
	"github.com/anonimpopov/hw4/internal/service"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/juju/zaputil/zapctx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/riandyrn/otelchi"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"moul.io/chizap"
)

// @title Auth API
// @version 1.0
// @description This is a simple auth server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:9000
// @BasePath /api/v1
// @query.collection.format multi

// @securityDefinitions.basic BasicAuth

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

// @securitydefinitions.oauth2.application OAuth2Application
// @tokenUrl https://example.com/oauth/token
// @scope.write Grants write access
// @scope.admin Grants read and write access to administrative information

// @securitydefinitions.oauth2.implicit OAuth2Implicit
// @authorizationurl https://example.com/oauthorize
// @scope.write Grants write access
// @scope.admin Grants read and write access to administrative information

// @securitydefinitions.oauth2.password OAuth2Password
// @tokenUrl /v1/login
// @scope.read Grants read access
// @scope.write Grants write access
// @scope.admin Grants read and write access to administrative information

// @securitydefinitions.oauth2.accessCode OAuth2AccessCode
// @tokenUrl https://example.com/oauth/token
// @authorizationurl https://example.com/oauthorize
// @scope.admin Grants read and write access to administrative information

// @x-extension-openapi {"example": "value on a json format"}

type adapter struct {
	config *Config

	authService service.Auth

	server *http.Server

	logging *zap.Logger

	trace trace.Tracer
}

// Auth godoc
// @Summary authorize login and password
// @Description authorize user by login and password
// @Accept json
// @Param credentials body Credentials{} false "user credentials"
// @Success 200 {object} model.TokenPair
// @Failure 403 {object} Error
// @Failure 404 {object} Error
// @Failure 500 {object} Error
// @Router /login [post]
func (a *adapter) Login(w http.ResponseWriter, r *http.Request) {
	newCtx, span := a.trace.Start(r.Context(), "/login")
	defer span.End()
	ctx := zapctx.WithLogger(newCtx, a.logging)
	span.SetAttributes(attribute.String("controller", "auth"))

	var credentials Credentials

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		a.logging.Error("Error decoding user credentials from json", zap.Error(err))
		writeError(w, err)
		return
	}

	span.AddEvent("Credentials decoded", trace.WithAttributes(attribute.String("login", credentials.Login)))

	tokenPair, err := a.authService.Login(ctx, credentials.Login, credentials.Password)
	if err != nil {
		a.logging.Error("Error loging user and getting tokenPair", zap.Error(err))
		writeError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.AccessTokenCookie,
		Value:    tokenPair.AccessToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.RefreshTokenCookie,
		Value:    tokenPair.RefreshToken,
		Path:     "/",
		HttpOnly: true,
	})

	a.logging.Info("User logged in")
	writeJSONResponse(w, http.StatusOK, tokenPair)
}

// Auth godoc
// @Summary validate authorization
// @Description validate authorization
// @Success 200 {object} model.TokenPair
// @Failure 403 {object} Error
// @Failure 500 {object} Error
// @Router /validate [post]
func (a *adapter) Validate(w http.ResponseWriter, r *http.Request) {
	newCtx, span := a.trace.Start(r.Context(), "/validate")
	defer span.End()
	ctx := zapctx.WithLogger(newCtx, a.logging)
	span.SetAttributes(attribute.String("controller", "auth"))

	accessToken, err := r.Cookie(a.config.AccessTokenCookie)
	if err != nil {
		a.logging.Error("Error reading accessToken cookie in validate", zap.Error(err))
		writeError(w, fmt.Errorf("%w: %s", service.ErrForbidden, err))
		return
	}

	refreshToken, _ := r.Cookie(a.config.RefreshTokenCookie)
	if err != nil {
		a.logging.Error("Error reading RefreshTokenCookie cookie in validate", zap.Error(err))
		writeError(w, fmt.Errorf("%w: %s", service.ErrForbidden, err))
		return
	}

	tokenPair := &model.TokenPair{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}

	tokenPair, err = a.authService.ValidateAndRefresh(ctx, tokenPair)
	if err != nil {
		a.logging.Error("Error validating and refreshing tokenPair", zap.Error(err))
		writeError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.AccessTokenCookie,
		Value:    tokenPair.AccessToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.RefreshTokenCookie,
		Value:    tokenPair.RefreshToken,
		Path:     "/",
		HttpOnly: true,
	})

	writeJSONResponse(w, http.StatusOK, tokenPair)
}

// Auth godoc
// @Summary logout user
// @Description logout user
// @Success 200
// @Router /logout [post]
func (a *adapter) Logout(w http.ResponseWriter, r *http.Request) {
	_, span := a.trace.Start(r.Context(), "/validate")
	defer span.End()
	span.SetAttributes(attribute.String("controller", "auth"))

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.AccessTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.RefreshTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
}

var (
	requestsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "api_requests_total",
			Help: "Total number of HTTP requests for every url.",
		},
		[]string{"method", "endpoint"},
	)
	methodsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "api_methods_total",
			Help: "Total number of HTTP requests for every method.",
		},
		[]string{"method"},
	)
	requestsCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "api_requests_count",
			Help: "Total number of requests.",
		},
	)
)

func PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		methodsTotal.WithLabelValues(r.Method).Inc()
		requestsCount.Inc()
		next.ServeHTTP(w, r)
	})
}

// Serve uses otelchi and swagger
func (a *adapter) Serve() error {
	//r := chi.NewRouter()
	r := chi.NewRouter()

	// Open Telemetry
	r.Use(otelchi.Middleware("main", otelchi.WithChiRoutes(r)))

	r.Use(middleware.RequestID)

	r.Use(chizap.New(a.logging, &chizap.Opts{
		WithReferer:   true,
		WithUserAgent: true,
	}))

	r.Use(PrometheusMiddleware)

	r.Post("/login", http.HandlerFunc(a.Login))
	r.Post("/validate", http.HandlerFunc(a.Validate))
	r.Post("/logout", http.HandlerFunc(a.Logout))
	// установка маршрута для документации
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL(fmt.Sprintf("%s/swagger/doc.json", a.config.BasePath)))) // Адрес, по которому будет доступен doc.json

	r.Mount(a.config.BasePath, r)

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	r.Handle("/metrics", promhttp.Handler())

	//r.Handle("/metrics", promhttp.Handler())

	a.server = &http.Server{Addr: a.config.ServeAddress, Handler: r}

	if a.config.UseTLS {
		return a.server.ListenAndServeTLS(a.config.TLSCrtFile, a.config.TLSKeyFile)
	}

	return a.server.ListenAndServe()
}

func (a *adapter) Shutdown(ctx context.Context) {
	_ = a.server.Shutdown(ctx)
}

func New(
	config *Config,
	authorizer service.Auth,
	logger *zap.Logger,
	tracer trace.Tracer) Adapter {

	if config.SwaggerAddress != "" {
		docs.SwaggerInfo.Host = config.SwaggerAddress
	} else {
		docs.SwaggerInfo.Host = config.ServeAddress
	}

	docs.SwaggerInfo.BasePath = config.BasePath

	return &adapter{
		config:      config,
		authService: authorizer,
		logging:     logger,
		trace:       tracer,
	}
}
