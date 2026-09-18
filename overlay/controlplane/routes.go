package controlplane

import "fmt"

// RouteTemplate defines an HTTP method and path template for the overlay v1 control plane.
type RouteTemplate struct {
	Method string
	Path   string
}

var (
	RouteSigningKeys = RouteTemplate{
		Method: "GET",
		Path:   "/api/overlay/v1/signing-keys",
	}
	RouteSignedConfig = RouteTemplate{
		Method: "GET",
		Path:   "/api/overlay/v1/signed-config",
	}
	RouteSignedConfigAck = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/signed-config/:generation/ack",
	}
	RouteJoinTokensExchange = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/join-tokens/exchange",
	}
	RouteEnrollmentSignedConfig = RouteTemplate{
		Method: "GET",
		Path:   "/api/overlay/v1/enrollment/signed-config",
	}
	RouteEnrollmentSignedConfigAck = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/enrollment/signed-config/:generation/ack",
	}
	RouteDeviceSession = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/device/session",
	}
	RouteRegistrations = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/registrations",
	}
	RouteRegistrationsExchange = RouteTemplate{
		Method: "POST",
		Path:   "/api/overlay/v1/registrations/:registrationID/exchange",
	}
	RoutePolicyArtifact = RouteTemplate{
		Method: "GET",
		Path:   "/api/overlay/v1/enrollment/policy-artifacts/:generation/:digest",
	}
)

// ClientOverlayRoutes returns all route templates used by the client when communicating with accounts overlay control plane.
var ClientOverlayRoutes = []RouteTemplate{
	RouteSigningKeys,
	RouteSignedConfig,
	RouteSignedConfigAck,
	RouteJoinTokensExchange,
	RouteEnrollmentSignedConfig,
	RouteEnrollmentSignedConfigAck,
	RouteDeviceSession,
	RouteRegistrations,
	RouteRegistrationsExchange,
	RoutePolicyArtifact,
}

// BuildSignedConfigAckPath formats an ack route with the given generation.
func BuildSignedConfigAckPath(generation uint64) string {
	return fmt.Sprintf("/api/overlay/v1/signed-config/%d/ack", generation)
}

// BuildEnrollmentSignedConfigAckPath formats an enrollment ack route with the given generation.
func BuildEnrollmentSignedConfigAckPath(generation uint64) string {
	return fmt.Sprintf("/api/overlay/v1/enrollment/signed-config/%d/ack", generation)
}

// BuildRegistrationsExchangePath formats a registration exchange route.
func BuildRegistrationsExchangePath(registrationID string) string {
	return fmt.Sprintf("/api/overlay/v1/registrations/%s/exchange", registrationID)
}

// BuildPolicyArtifactPath formats an artifact route.
func BuildPolicyArtifactPath(generation uint64, digest string) string {
	return fmt.Sprintf("/api/overlay/v1/enrollment/policy-artifacts/%d/%s", generation, digest)
}
