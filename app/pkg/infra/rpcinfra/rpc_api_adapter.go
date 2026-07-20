package rpcinfra

import (
	"context"

	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra/rpcerrors"
)

// JSONRPCAPIAdapter adapts the set of operations that are supported by the RPC protocol
type JSONRPCAPIAdapter interface {
	// AdaptGenerateAccount adapts the generation of an Ethereum account.
	AdaptGenerateAccount(ctx context.Context, data GenerateAccountRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptGenerateAccountsV2 adapts the generation of one ECDSA key-pair and optional PQ key-pairs.
	AdaptGenerateAccountsV2(ctx context.Context, data GenerateAccountsV2RequestParams) (*GenerateAccountsV2Response, *rpcerrors.RPCError)
	// AdaptRemoveAccount adapts the removal of an Ethereum account.
	AdaptRemoveAccount(ctx context.Context, data RemoveAccountRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptListAccounts adapts the listing of all the Ethereum accounts in an Application.
	AdaptListAccounts(ctx context.Context, data ListAccountsRequestParams) ([]string, *rpcerrors.RPCError)
	// AdaptSignTx adapts the signature of a transaction with an Ethereum account.
	AdaptSignTx(ctx context.Context, data SignTXRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptSignTxV2 adapts the signature of a transaction with support for multiple algorithms.
	AdaptSignTxV2(ctx context.Context, data SignTXV2RequestParams) (*SignTXV2Response, *rpcerrors.RPCError)
	// AdaptVerify adapts the verification of a signature over arbitrary data.
	AdaptVerify(ctx context.Context, data VerifyRequestParams) (*VerifyResponse, *rpcerrors.RPCError)
	// AdaptGetPK adapts retrieval of a public key for a given (from, algorithm).
	AdaptGetPK(ctx context.Context, data GetPKRequestParams) (*GetPKResponse, *rpcerrors.RPCError)
}
