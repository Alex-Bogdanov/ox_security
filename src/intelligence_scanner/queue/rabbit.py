from collections.abc import Awaitable, Callable

import aio_pika
import orjson

from .schemas import ScanJob


class RabbitPublisher:

    def __init__(self, rabbitmq_url: str, queue_name: str) -> None:
        self._rabbitmq_url = rabbitmq_url
        self._queue_name = queue_name
        self._connection: aio_pika.RobustConnection | None = None
        self._channel: aio_pika.RobustChannel | None = None

    async def connect(self) -> None:
        self._connection = await aio_pika.connect_robust(self._rabbitmq_url)
        self._channel = await self._connection.channel()

        await self._channel.declare_queue(
            self._queue_name,
            durable=True,
        )

    async def publish_scan_job(self, job: ScanJob) -> None:
        if self._channel is None:
            raise RuntimeError("RabbitPublisher is not connected")

        body = orjson.dumps(job.model_dump(mode="json", by_alias=True))

        message = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
        )

        await self._channel.default_exchange.publish(
            message,
            routing_key=self._queue_name,
        )

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()


class RabbitConsumer:

    def __init__(
        self,
        rabbitmq_url: str,
        queue_name: str,
        prefetch_count: int,
    ) -> None:
        self._rabbitmq_url = rabbitmq_url
        self._queue_name = queue_name
        self._prefetch_count = prefetch_count
        self._connection: aio_pika.RobustConnection | None = None
        self._channel: aio_pika.RobustChannel | None = None
        self._queue: aio_pika.RobustQueue | None = None

    async def connect(self) -> None:
        self._connection = await aio_pika.connect_robust(self._rabbitmq_url)
        self._channel = await self._connection.channel()
        await self._channel.set_qos(prefetch_count=self._prefetch_count)

        self._queue = await self._channel.declare_queue(
            self._queue_name,
            durable=True,
        )

    async def consume(self, handler: Callable[[ScanJob], Awaitable[None]]) -> None:
        if self._queue is None:
            raise RuntimeError("RabbitConsumer is not connected")

        async with self._queue.iterator() as queue_iterator:
            async for message in queue_iterator:
                # requeue=False is intentional. Worker errors are persisted in Mongo as failed.
                # Later we can add DLX/retry policy.
                async with message.process(requeue=False):
                    payload = orjson.loads(message.body)
                    job = ScanJob.model_validate(payload)
                    await handler(job)

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
