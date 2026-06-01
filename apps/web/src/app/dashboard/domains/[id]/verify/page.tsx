import { VerifyDomainClient } from './VerifyDomainClient'

export default async function VerifyDomainPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <VerifyDomainClient id={id} />
}
