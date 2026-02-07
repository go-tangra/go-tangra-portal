package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/transcoder"
)

// ProviderTranscoderSet provides the transcoder components
var ProviderTranscoderSet = wire.NewSet(
	transcoder.NewDescriptorParser,
	transcoder.NewRequestBuilder,
	transcoder.NewResponseTransformer,
	transcoder.NewTranscoder,
)
