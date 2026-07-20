package hsmconnector

import (
	"context"
	"fmt"
	"math/big"

	"github.com/asaskevich/govalidator"
	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/hyperledger-labs/signare/app/pkg/commons/logger"
	"github.com/hyperledger-labs/signare/app/pkg/entities"
	"github.com/hyperledger-labs/signare/app/pkg/internal/errors"
	"github.com/hyperledger-labs/signare/app/pkg/signaturemanager"
)

// HSMConnector connects with the HSM and operates with it.
type HSMConnector interface {
	// GenerateAddress generates a key pair in the underlying signature manager and returns the Ethereum address or an error if it fails.
	GenerateAddress(ctx context.Context, input GenerateAddressInput) (*GenerateAddressOutput, error)
	// GenerateKeys generates one ECDSA key-pair and, optionally, additional PQ key-pairs.
	GenerateKeys(ctx context.Context, input GenerateKeysInput) (*GenerateKeysOutput, error)
	// RemoveAddress removes the key pair associated with the given Ethereum address.
	RemoveAddress(ctx context.Context, input RemoveAddressInput) (*RemoveAddressOutput, error)
	// ListAddresses lists the addresses associated with their corresponding key pairs that exist in all the slots of an application.
	ListAddresses(ctx context.Context, input ListAddressesInput) (*ListAddressesOutput, error)
	// SignTx signs an Ethereum transaction using the private key associated with the address specific in the "From" input attribute.
	SignTx(ctx context.Context, input SignTxInput) (*SignTxOutput, error)
	// SignTxV2 signs an Ethereum transaction with support for multiple algorithms.
	SignTxV2(ctx context.Context, input SignTxV2Input) (*SignTxV2Output, error)
	// Verify verifies a signature over arbitrary data using the key identified by (From, Algorithm).
	Verify(ctx context.Context, input VerifyInput) (*VerifyOutput, error)
	// CloseAll closes all signature manager resources.
	CloseAll(ctx context.Context, input CloseAllInput) (*CloseAllOutput, error)
	// IsAlive checks the availability of a given slot.
	IsAlive(ctx context.Context, input IsAliveInput) (*IsAliveOutput, error)
	// Reset updates the state of the snapshot taken by the HSM library.
	Reset(ctx context.Context, input ResetInput) (*ResetOutput, error)
}

const (
	signatureLength           = 65
	minSignatureOffsetBitcoin = 27
	maxSignatureOffsetBitcoin = 35
)

func (d DefaultUseCase) GenerateAddress(ctx context.Context, input GenerateAddressInput) (*GenerateAddressOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "GenerateAddress")

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, createErr
	}

	generateKeyInput := signaturemanager.GenerateKeyInput{
		Slot:   input.Slot,
		Pin:    input.Pin,
		Tracer: tracer,
	}
	generateKeyOutput, generateKeyErr := digitalSignatureManager.GenerateKey(ctx, generateKeyInput)
	if generateKeyErr != nil {
		if signaturemanager.IsInvalidSlotError(generateKeyErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(generateKeyErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(err)
	}

	tracer.Debugf("generated address: '%s'", generateKeyOutput.Address.String())

	return &GenerateAddressOutput{
		Address: generateKeyOutput.Address,
	}, nil
}

// GenerateKeys generates one ECDSA key-pair and, if requested, additional PQ key-pairs.
// Behaviour:
//   - Always generates exactly one ECDSA(secp256k1) key-pair.
//   - If input.PQ == true, it also generates len(input.Algorithms) PQ key-pairs,
//     using each algorithm string provided.
func (d DefaultUseCase) GenerateKeys(ctx context.Context, input GenerateKeysInput) (*GenerateKeysOutput, error) {
	// Validate the slot connection data only. PQ/Algorithms are validated at business level.
	_, err := govalidator.ValidateStruct(input.SlotConnectionData)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "GenerateKeys")
	tracer.AddProperty("pq", input.PQ)

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, createErr
	}

	result := make([]GeneratedKey, 0)

	// 1) Always generate one ECDSA key-pair.
	ecdsaGenerateInput := signaturemanager.GenerateKeyInput{
		Slot:      input.Slot,
		Pin:       input.Pin,
		Tracer:    tracer,
		Algorithm: signaturemanager.KeyAlgorithmECDSAsecp256k1,
	}
	ecdsaOut, ecdsaErr := digitalSignatureManager.GenerateKey(ctx, ecdsaGenerateInput)
	if ecdsaErr != nil {
		if signaturemanager.IsInvalidSlotError(ecdsaErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(ecdsaErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(ecdsaErr)
	}
	tracer.Debugf("generated ECDSA address: '%s'", ecdsaOut.Address.String())
	result = append(result, GeneratedKey{
		Type:      KeyGenerationKindECDSA,
		Algorithm: string(signaturemanager.KeyAlgorithmECDSAsecp256k1),
		Address:   &ecdsaOut.Address,
	})

	// 2) Optionally generate PQ keys.
	if input.PQ {
		for _, algo := range input.Algorithms {
			pqGenerateInput := signaturemanager.GenerateKeyInput{
				Slot:      input.Slot,
				Pin:       input.Pin,
				Tracer:    tracer,
				Algorithm:    signaturemanager.KeyAlgorithmKind(algo),
				OwnerAddress: &ecdsaOut.Address,
			}
			pqOut, pqErr := digitalSignatureManager.GenerateKey(ctx, pqGenerateInput)
			if pqErr != nil {
				// If a PQ algorithm is not supported or fails, bubble up as internal error for now.
				return nil, errors.InternalFromErr(pqErr)
			}
			result = append(result, GeneratedKey{
				Type:      KeyGenerationKindPQ,
				Algorithm: algo,
				Address:   &ecdsaOut.Address,
				PublicKey: pqOut.PublicKey,
				Label:     pqOut.Label,
			})
		}
	}

	return &GenerateKeysOutput{Keys: result}, nil
}

func (d DefaultUseCase) RemoveAddress(ctx context.Context, input RemoveAddressInput) (*RemoveAddressOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "RemoveAddress")

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error removing address: %s", err.Error())
	}

	removeKeyInput := signaturemanager.RemoveKeyInput{
		Slot:    input.Slot,
		Pin:     input.Pin,
		Tracer:  tracer,
		Address: input.Address,
	}
	_, err = digitalSignatureManager.RemoveKey(ctx, removeKeyInput)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(err).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		if signaturemanager.IsNotFoundError(err) {
			msg := fmt.Sprintf("key for address [%s] not found", input.Address.String())
			return nil, errors.NotFoundFromErr(err).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(err).WithMessage("error removing address: %s", err.Error())
	}

	tracer.Trace(fmt.Sprintf("removed address: '%s'", removeKeyInput.Address.String()))

	return &RemoveAddressOutput{
		Address: input.Address,
	}, nil
}

func (d DefaultUseCase) ListAddresses(ctx context.Context, input ListAddressesInput) (*ListAddressesOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "ListAddresses")

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error connecting to the digital signature manager: %s", createErr.Error())
	}

	listKeysInput := signaturemanager.ListKeysInput{
		Slot:   input.Slot,
		Pin:    input.Pin,
		Tracer: tracer,
	}
	keys, listKeysErr := digitalSignatureManager.ListKeys(ctx, listKeysInput)
	if listKeysErr != nil {
		if signaturemanager.IsInvalidSlotError(listKeysErr) {
			logger.LogEntry(ctx).Warnf("could not obtain keys from the configured HSM slot '%s' because it does not exist in the HSM of type '%s'", input.Slot, input.ModuleKind)
		}
		return nil, errors.InternalFromErr(listKeysErr).WithMessage("error listing addresses: %s", listKeysErr.Error())
	}

	return &ListAddressesOutput{
		Items: keys.Items,
	}, nil
}

func (d DefaultUseCase) SignTx(ctx context.Context, input SignTxInput) (*SignTxOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	if input.From.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'from' cannot be empty")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "SignTx")

	gas := entities.NewHexUInt64(90000) // as defined in https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_signtransaction
	if input.Gas != nil {
		gas = *input.Gas
	}

	defaultGasPrice := entities.NewHexInt256(big.NewInt(0))
	gasPrice := *defaultGasPrice
	if input.GasPrice != nil {
		gasPrice = *input.GasPrice
	}

	chainID := entities.NewHexInt256(input.ChainID.BigInt())

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error signing transaction: %s", createErr.Error())
	}
	if input.To == nil {
		tracer.AddProperty("to", "null")
	} else {
		tracer.AddProperty("to", input.To.String())
	}

	transaction := EthereumTransaction{
		From:     input.From,
		To:       input.To,
		Gas:      gas,
		GasPrice: gasPrice,
		Value:    input.Value,
		Data:     input.Data,
		Nonce:    input.Nonce,
		ChainID:  *chainID,
	}
	payload, err := transaction.Hash()
	if err != nil {
		return nil, err
	}

	signInput := signaturemanager.SignInput{
		Slot:   input.Slot,
		Pin:    input.Pin,
		Tracer: tracer,
		From:   input.From,
		Data:   *payload,
	}
	signOutput, signErr := digitalSignatureManager.Sign(ctx, signInput)
	if signErr != nil {
		if signaturemanager.IsInvalidSlotError(signErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(signErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(signErr)
	}

	signature := signatureToLowS(signOutput.Signature)
	// As Ethereum requires it, determining the V value for the signature so that the public key can be recovered from the signature.
	// The V value is used to discriminate between the two possible x-axis value for the elliptic curve equation.
	signatureWithV := make([]byte, signatureLength)
	copy(signatureWithV[1:], signature)
	recovered := false
	for i := minSignatureOffsetBitcoin; i < maxSignatureOffsetBitcoin; i++ { // iterate over the possible solutions for the elliptic curve equation
		// btcec lib format with the recovery ID (v) at the beginning
		signatureWithV[0] = byte(i)
		recoveredPublicKey, _, recoverCompactErr := btcececdsa.RecoverCompact(signatureWithV, *payload)
		if recoverCompactErr != nil {
			tracer.Errorf("EC Recover failed. Error: %v", recoverCompactErr)
			continue
		}
		if recoveredPublicKey != nil {
			pubKey, unmarshalECDSAKeyErr := unmarshalECDSAKey(recoveredPublicKey.SerializeUncompressed())
			if unmarshalECDSAKeyErr != nil {
				tracer.Errorf("unable to unmarshal public key after signing for address '%s'. Error: %v", input.From.String(), unmarshalECDSAKeyErr)
				continue
			}
			recoveredAddr, deriveAddressFromPublicKeyErr := signaturemanager.DeriveAddressFromPublicKey(pubKey.SerializeUncompressed())
			if deriveAddressFromPublicKeyErr != nil {
				return nil, deriveAddressFromPublicKeyErr
			}
			if recoveredAddr.String() == input.From.String() {
				recovered = true
				break
			}
		}
	}
	if !recovered {
		return nil, errors.Internal().WithMessage("error signing transaction: unable to find EC recovery value for address '%s'", input.From.String())
	}

	transactionSignature := generateEthereumTransactionSignature(signatureWithV, *chainID)
	transaction.Signature = transactionSignature

	tracer.Debug("generated transaction signature")

	transactionRLPEncode, err := transaction.RLPEncode()
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error signing transaction: failed to RLP encode transaction with '%v'", err.Error())
	}
	result := transactionRLPEncode.Encode()

	return &SignTxOutput{
		SignedTx:    result,
		Transaction: transaction,
	}, nil
}

// SignTxV2 behaves like SignTx but supports selecting the signing algorithm.
// If Algorithm is empty or corresponds to ECDSA, it behaves like SignTx and
// returns a standard Ethereum signed transaction (SignedTx) plus TxHash.
// For PQ algorithms, it signs the same TxHash with the PQ private key and
// returns TxHash and the raw signature, without constructing an Ethereum RLP
// transaction.
func (d DefaultUseCase) SignTxV2(ctx context.Context, input SignTxV2Input) (*SignTxV2Output, error) {
	// Reuse validation rules from SignTxInput where applicable.
	// We validate SlotConnectionData and From similarly.
	if input.From.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'from' cannot be empty")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "SignTxV2")

	gas := entities.NewHexUInt64(90000)
	if input.Gas != nil {
		gas = *input.Gas
	}

	defaultGasPrice := entities.NewHexInt256(big.NewInt(0))
	gasPrice := *defaultGasPrice
	if input.GasPrice != nil {
		gasPrice = *input.GasPrice
	}

	chainID := entities.NewHexInt256(input.ChainID.BigInt())

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error signing transaction: %s", createErr.Error())
	}
	if input.To == nil {
		tracer.AddProperty("to", "null")
	} else {
		tracer.AddProperty("to", input.To.String())
	}

	transaction := EthereumTransaction{
		From:     input.From,
		To:       input.To,
		Gas:      gas,
		GasPrice: gasPrice,
		Value:    input.Value,
		Data:     input.Data,
		Nonce:    input.Nonce,
		ChainID:  *chainID,
	}
	payload, err := transaction.Hash()
	if err != nil {
		return nil, err
	}

	// Decide algorithm. Empty means ECDSA.
	algorithm := input.Algorithm
	if algorithm == "" {
		algorithm = string(signaturemanager.KeyAlgorithmECDSAsecp256k1)
	}

	// ECDSA path: delegate to existing SignTx to keep Ethereum semantics.
	if algorithm == string(signaturemanager.KeyAlgorithmECDSAsecp256k1) {
		legacyInput := SignTxInput{
			SlotConnectionData: input.SlotConnectionData,
			From:             input.From,
			To:               input.To,
			Gas:              input.Gas,
			GasPrice:         input.GasPrice,
			Value:            input.Value,
			Data:             input.Data,
			Nonce:            input.Nonce,
		}
		legacyOut, legacyErr := d.SignTx(ctx, legacyInput)
		if legacyErr != nil {
			return nil, legacyErr
		}
		// Additionally, produce a raw ECDSA signature over the txHash so that
		// callers of eth_signTransactionV2 can also obtain a detached signature
		// for verification APIs.
		signInput := signaturemanager.SignInput{
			Slot:      input.Slot,
			Pin:       input.Pin,
			Tracer:    tracer,
			From:      input.From,
			Data:      *payload,
			Algorithm: signaturemanager.KeyAlgorithmECDSAsecp256k1,
		}
		signOutput, signErr := digitalSignatureManager.Sign(ctx, signInput)
		if signErr != nil {
			if signaturemanager.IsInvalidSlotError(signErr) {
				msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
				return nil, errors.PreconditionFailedFromErr(signErr).WithMessage(msg).SetHumanReadableMessage(msg)
			}
			return nil, errors.InternalFromErr(signErr)
		}
		txHashHex := payload.String()
		sigHex := entities.NewHexBytes(signOutput.Signature).String()
		return &SignTxV2Output{
			SignedTx: &legacyOut.SignedTx,
			TxHash:   txHashHex,
			Algorithm: algorithm,
			Signature: &sigHex,
		}, nil
	}

	// PQ (or other non-ECDSA) path: sign payload using the selected algorithm
	// and return raw signature and txHash.
	signInput := signaturemanager.SignInput{
		Slot:      input.Slot,
		Pin:       input.Pin,
		Tracer:    tracer,
		From:      input.From,
		Data:      *payload,
		Algorithm: signaturemanager.KeyAlgorithmKind(algorithm),
	}
	signOutput, signErr := digitalSignatureManager.Sign(ctx, signInput)
	if signErr != nil {
		if signaturemanager.IsInvalidSlotError(signErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(signErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(signErr)
	}

	txHashHex := payload.String()
	sigHex := entities.NewHexBytes(signOutput.Signature).String()
	return &SignTxV2Output{
		SignedTx: nil,
		TxHash:   txHashHex,
		Algorithm: algorithm,
		Signature: &sigHex,
	}, nil
}

// Verify checks whether the given signature is valid for the provided data and key.
// It uses the same deterministic labeling scheme as SignTxV2 to locate the key
// inside the HSM.
func (d DefaultUseCase) Verify(ctx context.Context, input VerifyInput) (*VerifyOutput, error) {
	_, err := govalidator.ValidateStruct(input.SlotConnectionData)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	if input.From.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'from' cannot be empty")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "Verify")

	alg := input.Algorithm
	if alg == "" {
		alg = string(signaturemanager.KeyAlgorithmECDSAsecp256k1)
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error verifying signature: %s", createErr.Error())
	}

	verifyInput := signaturemanager.VerifyInput{
		Slot:      input.Slot,
		Pin:       input.Pin,
		Tracer:    tracer,
		From:      input.From,
		Data:      input.Data,
		Signature: input.Signature,
		Algorithm: signaturemanager.KeyAlgorithmKind(alg),
	}
	verifyOutput, verifyErr := digitalSignatureManager.Verify(ctx, verifyInput)
	if verifyErr != nil {
		if signaturemanager.IsInvalidSlotError(verifyErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(verifyErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(verifyErr)
	}

	return &VerifyOutput{
		Result:    verifyOutput.Result,
		PublicKey: verifyOutput.PublicKey,
	}, nil
}

func (d DefaultUseCase) CloseAll(ctx context.Context, _ CloseAllInput) (*CloseAllOutput, error) {
	_, err := d.digitalSignatureManagerFactory.Close(ctx, CloseInput{})
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error closing digital signature manager: %v", err)
	}

	logger.LogEntry(ctx).Debug("closed digital signature manager")

	return &CloseAllOutput{}, nil
}

func (d DefaultUseCase) IsAlive(ctx context.Context, input IsAliveInput) (*IsAliveOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "IsAlive")

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error checking if digital signature manager is alive: %v", createErr.Error())
	}

	isAliveInput := signaturemanager.IsAliveInput{
		Slot:   input.Slot,
		Pin:    input.Pin,
		Tracer: tracer,
	}
	isAliveOutput, isAliveOutputErr := digitalSignatureManager.IsAlive(ctx, isAliveInput)
	if isAliveOutputErr != nil {
		if signaturemanager.IsInvalidSlotError(isAliveOutputErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.PreconditionFailedFromErr(isAliveOutputErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		if signaturemanager.IsPinIncorrectError(isAliveOutputErr) {
			msg := fmt.Sprintf("the pin provided for the slot '%s' is not correct", input.Slot)
			return nil, errors.PreconditionFailedFromErr(isAliveOutputErr).WithMessage(msg).SetHumanReadableMessage(msg)
		}
		return nil, errors.InternalFromErr(isAliveOutputErr)
	}

	tracer.Debugf("checked if slot '%s' is alive, with result: '%t'", input.Slot, isAliveOutput.IsAlive)

	return &IsAliveOutput{
		IsAlive: isAliveOutput.IsAlive,
	}, nil
}

func (d DefaultUseCase) Reset(ctx context.Context, input ResetInput) (*ResetOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	resetErr := d.digitalSignatureManagerFactory.Reset(ctx, input.ModuleKind)
	if resetErr != nil {
		return nil, errors.InternalFromErr(resetErr).WithMessage("failed to reset digital signature manager: %v", resetErr.Error())
	}

	logger.LogEntry(ctx).Debug("reset digital signature manager")

	return &ResetOutput{}, nil
}

var _ HSMConnector = new(DefaultUseCase)

// DefaultUseCase implements the HSMConnector interface.
type DefaultUseCase struct {
	digitalSignatureManagerFactory DigitalSignatureManagerFactory
}

// DefaultUseCaseOptions options to create a new DefaultUseCase.
type DefaultUseCaseOptions struct {
	// DigitalSignatureManagerFactory defines the factory to create DigitalSignatureManager connections
	DigitalSignatureManagerFactory DigitalSignatureManagerFactory
}

// ProvideDefaultHSMConnector creates a new DefaultUseCase instance, returning an error if it fails.
func ProvideDefaultHSMConnector(options DefaultUseCaseOptions) (*DefaultUseCase, error) {
	if options.DigitalSignatureManagerFactory == nil {
		return nil, errors.Internal().WithMessage("mandatory 'DigitalSignatureManagerFactory' was not provided")
	}
	return &DefaultUseCase{
		digitalSignatureManagerFactory: options.DigitalSignatureManagerFactory,
	}, nil
}
