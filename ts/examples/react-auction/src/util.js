import { EXTRINSIC_VERSION } from '@polkadot/types/extrinsic/v4/Extrinsic';
import { createMetadata } from '@substrate/txwrapper-polkadot';

/**
 * Signing function. Implement this on the OFFLINE signing device.
 *
 * @param pair - The signing pair.
 * @param signingPayload - Payload to sign.
 */
export const signWith = (pair, signingPayload, options) => {
	const { registry, metadataRpc } = options;
	// Important! The registry needs to be updated with latest metadata, so make
	// sure to run `registry.setMetadata(metadata)` before signing.
	registry.setMetadata(createMetadata(registry, metadataRpc));

	const { signature } = registry
		.createType('ExtrinsicPayload', signingPayload, {
			version: EXTRINSIC_VERSION,
		})
		.sign(pair);

	return signature;
}
