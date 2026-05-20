<?php
namespace Frickmail\User;

class TaskHandler
{
	public function __construct(private Db $db) {}

	public function listTasks(int $userId, ?bool $completed = null, int $limit = 200): array
	{
		$rows = $this->db->listTasks($userId, $completed, $limit);
		return ['ok' => true, 'tasks' => $rows];
	}

	public function addTask(int $userId, string $title, ?string $notes, ?string $dueDate): array
	{
		if ('' === \trim($title)) {
			throw new \RuntimeException('title is required');
		}
		$id = $this->db->addTask($userId, $title, $notes, $dueDate);
		return ['ok' => true, 'id' => $id];
	}

	public function completeTask(int $userId, int $taskId, bool $completed): array
	{
		$ok = $this->db->completeTask($userId, $taskId, $completed);
		return ['ok' => $ok];
	}

	public function deleteTask(int $userId, int $taskId): array
	{
		$ok = $this->db->deleteTask($userId, $taskId);
		return ['ok' => $ok];
	}

	public function updateTask(int $userId, int $taskId, string $title, ?string $notes, ?string $dueDate): array
	{
		if ('' === \trim($title)) {
			throw new \RuntimeException('title is required');
		}
		$ok = $this->db->updateTask($userId, $taskId, $title, $notes, $dueDate);
		return ['ok' => $ok];
	}
}
