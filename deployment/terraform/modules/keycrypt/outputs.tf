output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.alb.dns_name
}

output "rds_endpoint" {
  description = "Postgres endpoint address"
  value       = aws_db_instance.postgres.address
}

output "rds_port" {
  value = aws_db_instance.postgres.port
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "s3_bucket" {
  value = aws_s3_bucket.data.id
}

output "kms_key_id" {
  value = aws_kms_key.data.key_id
}

output "ecs_cluster_id" {
  value = aws_ecs_cluster.ecs.id
}
