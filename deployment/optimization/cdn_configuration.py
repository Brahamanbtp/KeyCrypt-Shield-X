from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class CacheRule:
    pattern: str
    ttl_seconds: int
    behavior: str = 'cache'  # 'cache' or 'no-cache' or 'origin'
    compress: bool = True


@dataclass
class CDNConfiguration:
    provider: str
    origin: str
    distribution_id: Optional[str] = None
    config: Dict = field(default_factory=dict)
    cache_rules: List[CacheRule] = field(default_factory=list)
    edge_locations: List[str] = field(default_factory=list)


def configure_cdn(provider: str, origin: str, distribution_id: Optional[str] = None, **kwargs) -> CDNConfiguration:
    """Create a CDNConfiguration for CloudFront, Cloudflare, or Fastly.

    This function performs light-weight provider checks and returns a configuration
    object that can be used with other helper functions. Applying complex config
    changes to an existing distribution requires operator review and may be
    provider-specific.
    """
    provider = provider.lower()
    cfg = CDNConfiguration(provider=provider, origin=origin, distribution_id=distribution_id)

    if provider == 'cloudfront':
        try:
            import boto3
            cf = boto3.client('cloudfront')
            cfg.config['client'] = cf
            logger.info('CloudFront client initialized')
        except Exception:
            logger.exception('boto3/CloudFront client unavailable')

    if provider == 'cloudflare' or provider == 'cloudflare.com':
        # require CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID env vars
        token = os.environ.get('CLOUDFLARE_API_TOKEN')
        zone = os.environ.get('CLOUDFLARE_ZONE_ID')
        cfg.config['api_token'] = token
        cfg.config['zone_id'] = zone

    if provider == 'fastly':
        # Fastly client optional; require FASTLY_API_KEY
        key = os.environ.get('FASTLY_API_KEY')
        cfg.config['api_key'] = key

    # default cache rules
    cfg.cache_rules = [
        CacheRule(pattern='/api/*', ttl_seconds=0, behavior='no-cache', compress=False),
        CacheRule(pattern='/static/*', ttl_seconds=31536000, behavior='cache', compress=True),
        CacheRule(pattern='/docs/*', ttl_seconds=3600, behavior='cache', compress=True),
    ]
    return cfg


def set_cache_rules(cdn: CDNConfiguration, rules: List[CacheRule]) -> None:
    """Set cache rules in the `cdn` configuration and attempt to apply them to the provider.

    Note: For CloudFront, modifying cache behaviors requires retrieving the distribution
    config, editing, and calling `update_distribution`. This helper prepares the
    config and attempts to apply it if a boto3 client is available.
    """
    cdn.cache_rules = rules
    provider = cdn.provider

    if provider == 'cloudfront' and 'client' in cdn.config and cdn.distribution_id:
        cf = cdn.config['client']
        try:
            dist_id = cdn.distribution_id
            # fetch current config
            res = cf.get_distribution_config(Id=dist_id)
            etag = res['ETag']
            dist_cfg = res['DistributionConfig']
            # convert CacheBehaviors: append cache behaviors for rules (operator must review)
            cache_behaviors = dist_cfg.get('CacheBehaviors', {})
            items = cache_behaviors.get('Items', []) if isinstance(cache_behaviors, dict) else []
            for r in rules:
                behavior = {
                    'PathPattern': r.pattern.strip('/'),
                    'TargetOriginId': dist_cfg['Origins']['Items'][0]['Id'] if dist_cfg.get('Origins') else cdn.origin,
                    'ViewerProtocolPolicy': 'https-only' if r.behavior != 'no-cache' else 'redirect-to-https',
                    'MinTTL': 0,
                    'DefaultTTL': r.ttl_seconds,
                    'MaxTTL': r.ttl_seconds,
                    'Compress': r.compress,
                    'ForwardedValues': {'QueryString': False, 'Cookies': {'Forward': 'none'}},
                }
                items.append(behavior)
            dist_cfg['CacheBehaviors'] = {'Quantity': len(items), 'Items': items}
            # attempt to update (operator should inspect changes)
            cf.update_distribution(DistributionConfig=dist_cfg, Id=dist_id, IfMatch=etag)
            logger.info('CloudFront distribution updated with new cache behaviors (review recommended)')
        except Exception:
            logger.exception('Failed to apply CloudFront cache rules')
    else:
        logger.info('Cache rules set locally; provider apply step skipped (no client or distribution_id)')


def enable_compression(cdn: CDNConfiguration, types: Optional[List[str]] = None) -> None:
    """Enable Brotli/Gzip compression for specified content types.

    This updates local config and attempts to call provider APIs where possible.
    """
    types = types or ['text/html', 'text/css', 'application/javascript', 'application/json']
    cdn.config['compression'] = {'enabled': True, 'types': types}
    provider = cdn.provider
    if provider == 'cloudflare' and cdn.config.get('api_token'):
        # Cloudflare auto-minify and Brotli are account settings; attempt to set via API
        try:
            import requests
            zone = cdn.config.get('zone_id')
            token = cdn.config.get('api_token')
            if zone and token:
                headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
                # enable Brotli
                requests.patch(f'https://api.cloudflare.com/client/v4/zones/{zone}/settings/brotli', json={'value': 'on'}, headers=headers, timeout=10)
                # enable gzip via server (Cloudflare handles automatically)
                logger.info('requested Cloudflare compression settings')
        except Exception:
            logger.exception('failed to set Cloudflare compression settings')
    else:
        logger.info('Compression configured in object; provider apply step skipped or not supported programmatically')


def configure_edge_locations(cdn: CDNConfiguration, regions: List[str]) -> None:
    """Select preferred edge locations or geo-targeting regions for the CDN.

    Note: Provider APIs vary. For CloudFront you can set GeoRestriction/PriceClass; for Fastly/Cloudflare use pop pools.
    """
    cdn.edge_locations = regions
    provider = cdn.provider
    if provider == 'cloudfront' and 'client' in cdn.config and cdn.distribution_id:
        cf = cdn.config['client']
        try:
            dist_id = cdn.distribution_id
            res = cf.get_distribution_config(Id=dist_id)
            etag = res['ETag']
            dist_cfg = res['DistributionConfig']
            # Example: set PriceClass based on regions: PriceClass_All or PriceClass_200 etc.
            # This is a heuristic mapping; operator should choose exact PriceClass.
            dist_cfg['PriceClass'] = 'PriceClass_All'
            cf.update_distribution(DistributionConfig=dist_cfg, Id=dist_id, IfMatch=etag)
            logger.info('CloudFront distribution price class updated (operator review recommended)')
        except Exception:
            logger.exception('Failed to update CloudFront edge locations')
    else:
        logger.info('Edge location preferences recorded locally')


def invalidate_cache(cdn: CDNConfiguration, paths: List[str]) -> Dict[str, Any]:
    """Invalidate cache entries (paths) for the configured provider.

    Returns a provider-specific response dict.
    """
    provider = cdn.provider
    if provider == 'cloudfront' and 'client' in cdn.config and cdn.distribution_id:
        cf = cdn.config['client']
        caller = str(int(time.time()))
        try:
            res = cf.create_invalidation(DistributionId=cdn.distribution_id, InvalidationBatch={'Paths': {'Quantity': len(paths), 'Items': paths}, 'CallerReference': caller})
            logger.info('CloudFront invalidation created: %s', res.get('Invalidation', {}).get('Id'))
            return res
        except Exception:
            logger.exception('CloudFront invalidation failed')
            return {'error': 'cloudfront_failed'}

    if provider == 'cloudflare' and cdn.config.get('api_token') and cdn.config.get('zone_id'):
        try:
            import requests
            zone = cdn.config['zone_id']
            token = cdn.config['api_token']
            url = f'https://api.cloudflare.com/client/v4/zones/{zone}/purge_cache'
            headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
            resp = requests.post(url, json={'files': paths}, headers=headers, timeout=10)
            if resp.ok:
                logger.info('Cloudflare purge requested')
                return resp.json()
            else:
                logger.warning('Cloudflare purge failed: %s', resp.text)
                return {'error': 'cloudflare_failed', 'text': resp.text}
        except Exception:
            logger.exception('Cloudflare purge failed')
            return {'error': 'cloudflare_exception'}

    if provider == 'fastly' and cdn.config.get('api_key'):
        try:
            import requests
            key = cdn.config['api_key']
            service_id = cdn.distribution_id
            headers = {'Fastly-Key': key, 'Accept': 'application/json'}
            results = []
            for p in paths:
                resp = requests.post(f'https://api.fastly.com/service/{service_id}/purge', headers=headers, json={'path': p}, timeout=10)
                results.append({'path': p, 'status': resp.status_code})
            return {'results': results}
        except Exception:
            logger.exception('Fastly purge failed')
            return {'error': 'fastly_exception'}

    logger.info('No provider-specific invalidation performed; returning local info')
    return {'paths': paths, 'note': 'no-op; provider not configured or unsupported'}


def _example_usage():
    # Example workflow
    cdn = configure_cdn('cloudfront', origin='my-origin.example.com', distribution_id=os.environ.get('CLOUDFRONT_DIST_ID'))
    set_cache_rules(cdn, [
        CacheRule(pattern='/api/*', ttl_seconds=0, behavior='no-cache', compress=False),
        CacheRule(pattern='/static/*', ttl_seconds=31536000, behavior='cache', compress=True),
        CacheRule(pattern='/docs/*', ttl_seconds=3600, behavior='cache', compress=True),
    ])
    enable_compression(cdn)
    invalidate_cache(cdn, ['/static/app.v1.js'])


if __name__ == '__main__':
    _example_usage()
