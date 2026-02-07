package auth

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
)

// AccessTokenChecker 定义访问令牌检查接口
type AccessTokenChecker interface {
	// IsValidAccessToken 检查访问令牌是否有效
	IsValidAccessToken(ctx context.Context, userID uint32, accessToken string) bool

	// IsBlockedAccessToken 检查访问令牌是否被阻止
	IsBlockedAccessToken(ctx context.Context, userID uint32, accessToken string) bool
}

type AccessTokenCheckerFunc func(ctx context.Context, userID uint32, accessToken string) bool

func (f AccessTokenCheckerFunc) IsValidAccessToken(ctx context.Context, userID uint32, accessToken string) bool {
	return f(ctx, userID, accessToken)
}

type AccessTokenBlockerFunc func(ctx context.Context, userID uint32, accessToken string) bool

func (f AccessTokenBlockerFunc) IsBlockedAccessToken(ctx context.Context, userID uint32, accessToken string) bool {
	return f(ctx, userID, accessToken)
}

// composedChecker 将单独的 valid/block 函数组合成一个 AccessTokenChecker
type composedChecker struct {
	valid   AccessTokenCheckerFunc
	blocker AccessTokenBlockerFunc
}

// NewAccessTokenCheckerFromFuncs 构造组合检查器
func NewAccessTokenCheckerFromFuncs(valid AccessTokenCheckerFunc, blocker AccessTokenBlockerFunc) AccessTokenChecker {
	return &composedChecker{
		valid:   valid,
		blocker: blocker,
	}
}

func (c *composedChecker) IsValidAccessToken(ctx context.Context, userID uint32, accessToken string) bool {
	if c.valid == nil {
		// 默认认为有效（或根据需要返回 false）
		return true
	}
	return c.valid(ctx, userID, accessToken)
}

func (c *composedChecker) IsBlockedAccessToken(ctx context.Context, userID uint32, accessToken string) bool {
	if c.blocker == nil {
		// 默认不被阻止
		return false
	}
	return c.blocker(ctx, userID, accessToken)
}

type options struct {
	log *log.Helper

	accessTokenChecker                AccessTokenChecker // 访问令牌检查器
	enableCheckTokenExpiration        bool               // 是否启用访问令牌过期检查
	enableCheckRefreshTokenExpiration bool               // 是否启用刷新令牌过期检查
	enableCheckScopes                 bool               // 是否启用作用域检查
	enableCheckTokenValidity          bool               // 是否启用访问令牌有效性检查

	enableAuthz bool // 是否启用鉴权

	injectOperatorId bool
	injectTenantId   bool
	injectEnt        bool
	injectMetadata   bool
}

type Option func(*options)

// WithAccessTokenChecker 设置访问令牌检查器
func WithAccessTokenChecker(checker AccessTokenChecker) Option {
	return func(opts *options) {
		opts.accessTokenChecker = checker
	}
}

func WithAccessTokenCheckerFromFuncs(valid AccessTokenCheckerFunc, blocker AccessTokenBlockerFunc) Option {
	return func(opts *options) {
		opts.accessTokenChecker = NewAccessTokenCheckerFromFuncs(valid, blocker)
	}
}

// WithEnableCheckTokenExpiration 设置是否启用访问令牌过期检查
func WithEnableCheckTokenExpiration(enable bool) Option {
	return func(opts *options) {
		opts.enableCheckTokenExpiration = enable
	}
}

func WithEnableCheckRefreshTokenExpiration(enable bool) Option {
	return func(opts *options) {
		opts.enableCheckRefreshTokenExpiration = enable
	}
}

// WithEnableCheckScopes 设置是否启用作用域检查
func WithEnableCheckScopes(enable bool) Option {
	return func(opts *options) {
		opts.enableCheckScopes = enable
	}
}

// WithEnableCheckTokenValidity 设置是否启用访问令牌有效性检查
func WithEnableCheckTokenValidity(enable bool) Option {
	return func(opts *options) {
		opts.enableCheckTokenValidity = enable
	}
}

// WithInjectOperatorId 设置是否注入操作员ID
func WithInjectOperatorId(enable bool) Option {
	return func(opts *options) {
		opts.injectOperatorId = enable
	}
}

// WithInjectTenantId 设置是否注入租户ID
func WithInjectTenantId(enable bool) Option {
	return func(opts *options) {
		opts.injectTenantId = enable
	}
}

// WithInjectEnt 设置是否注入Ent客户端
func WithInjectEnt(enable bool) Option {
	return func(opts *options) {
		opts.injectEnt = enable
	}
}

// WithInjectMetadata 设置是否注入元数据
func WithInjectMetadata(enable bool) Option {
	return func(opts *options) {
		opts.injectMetadata = enable
	}
}

// WithEnableAuthority 设置是否启用鉴权
func WithEnableAuthority(enable bool) Option {
	return func(opts *options) {
		opts.enableAuthz = enable
	}
}

// WithLogger 设置日志记录器
func WithLogger(logger log.Logger) Option {
	return func(o *options) {
		o.log = log.NewHelper(log.With(logger, "module", "auth.middleware"))
	}
}
