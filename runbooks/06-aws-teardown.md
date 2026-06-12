# 06 — AWS teardown (랩 종료, 비용 0 수렴)

EKS 랩(Tier 1/2)을 끝낼 때. **누락 = 다음 달 청구.** 순서대로 확인·삭제하고 마지막에 잔여
과금 0을 증명한다. 참고: [`docs/aws-eks-path.md`](../docs/aws-eks-path.md) §4.

> 황금률: **띄운 날 내린다.** EKS 컨트롤플레인($0.10/hr)·NAT($0.045/hr)는 *유휴 상태에서도*
> 시간당 과금된다.

---

## 순서 (위에서부터)

**1) 클러스터 삭제(노드그룹 포함):**
```bash
eksctl delete cluster --name <name> --region <region> --wait
# (terraform로 만들었으면) terraform destroy -auto-approve
```
`eksctl`은 보통 자기가 만든 VPC/NAT/서브넷까지 지운다. 단, **수동 추가분은 남는다 → 아래 확인.**

**2) NAT Gateway + Elastic IP (조용한 폭탄):**
```bash
aws ec2 describe-nat-gateways --filter Name=state,Values=available --region <region> \
  --query 'NatGateways[].NatGatewayId'
# 남았으면: aws ec2 delete-nat-gateway --nat-gateway-id <id>
aws ec2 describe-addresses --region <region> --query 'Addresses[?AssociationId==null].AllocationId'
# 미사용 EIP는 과금됨: aws ec2 release-address --allocation-id <id>
```

**3) 로드밸런서(서비스가 만든 ALB/NLB):**
```bash
aws elbv2 describe-load-balancers --region <region> --query 'LoadBalancers[].LoadBalancerArn'
# 남았으면 삭제. (k8s Service type=LoadBalancer 잔재)
```

**4) EBS 볼륨 · 스냅샷:**
```bash
aws ec2 describe-volumes --filters Name=status,Values=available --region <region> \
  --query 'Volumes[].VolumeId'   # 'available'(미연결) 볼륨은 과금 → 삭제
```

**5) KMS 키 (즉시 삭제 불가):**
```bash
# 7~30일 대기 후 삭제 예약. 그 사이 $1/월 과금됨을 인지.
aws kms schedule-key-deletion --key-id <key> --pending-window-in-days 7
```

**6) ECR 이미지 · CloudWatch 로그그룹:**
```bash
aws ecr delete-repository --repository-name cloudsec-api --force --region <region>
aws logs describe-log-groups --region <region> --query 'logGroups[].logGroupName'  # /aws/eks/... 정리
```

**7) 잔여 과금 0 증명(다음날):**
```bash
aws ce get-cost-and-usage --time-period Start=<어제>,End=<오늘> \
  --granularity DAILY --metrics UnblendedCost
```
→ 0(또는 KMS $1만)이면 teardown 완료.

---

## 체크리스트 (복붙용)
- [ ] `eksctl delete cluster` 완료
- [ ] NAT Gateway 없음 / 미사용 EIP 해제
- [ ] ALB/NLB 잔재 없음
- [ ] available EBS 볼륨 없음
- [ ] KMS 키 삭제 예약(또는 보존 결정)
- [ ] ECR/CloudWatch 정리
- [ ] Budgets 알림 정상 / Cost Explorer 다음날 0 확인

## 다루지 않는 것
- 조직 차원 SCP/계정 정리, Savings Plan 환불(범위 밖).
- 데이터(S3 등) 보존정책 — 이 데모엔 영속 데이터 없음.
