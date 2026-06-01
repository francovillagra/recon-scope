import { ScanClient } from './ScanClient'

export default async function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <ScanClient id={id} />
}
