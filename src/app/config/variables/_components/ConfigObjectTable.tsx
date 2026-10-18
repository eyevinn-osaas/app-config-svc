'use client';

import { ConfigObject, ConfigObjectList } from '@/api_config';
import { useApiUrl } from '@/hooks/useApiUrl';
import {
  Button,
  Input,
  Pagination,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tooltip
} from '@nextui-org/react';
import {
  IconCheck,
  IconLock,
  IconLockOpen,
  IconPencil,
  IconTrash,
  IconX
} from '@tabler/icons-react';
import { useEffect, useMemo, useState } from 'react';
import NewConfigObjectModal from './NewConfigObjectModal';
import {
  createConfigObject,
  deleteConfigObject,
  getConfigObjectList,
  markConfigObjectAsSecret,
  updateConfigObject
} from '@/app/client';
import { ConfirmationModal } from '@/components/modal/ConfirmationModal';
import ClipBoardCopyButton from '@/components/button/ClipboardCopyButton';

export interface ConfigObjectTableProps {
  pageSize?: number;
}

const DEFAULT_PAGE_SIZE = 20;

interface TableItem {
  keyId: string;
  value: string;
  secret?: boolean;
}

export default function ConfigObjectTable({
  pageSize = DEFAULT_PAGE_SIZE
}: ConfigObjectTableProps) {
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState<ConfigObjectList | undefined>(undefined);
  const [editKeyId, setEditKeyId] = useState<string | undefined>(undefined);
  const [editValue, setEditValue] = useState<string | undefined>(undefined);
  const [isConfirmModalOpen, setConfirmModalOpen] = useState(false);

  const apiUrl = useApiUrl();

  const handleSaveEdit = (item: TableItem) => {
    if (editValue === undefined) {
      return;
    }

    // Guard: do not save an empty string for a secret item (the masked '***'
    // was never a real value the user typed — an empty submit would overwrite
    // the stored secret with an empty string).
    if (item.secret && editValue === '') {
      setEditKeyId(undefined);
      setEditValue(undefined);
      return;
    }

    if (!apiUrl) {
      return;
    }

    updateConfigObject({
      apiUrl,
      keyId: item.keyId,
      value: editValue,
      ...(item.secret ? { secret: true } : {})
    })
      .then(([data, error]) => {
        if (error) {
          console.error(error);
          return;
        }
        setEditValue(data?.value);
      })
      .finally(() => {
        setEditKeyId(undefined);
        updateTableContents();
      });
  };

  const handleMarkAsSecret = (item: TableItem) => {
    if (!apiUrl) {
      return;
    }
    markConfigObjectAsSecret({
      apiUrl,
      keyId: item.keyId,
      value: item.value
    })
      .then(([, error]) => {
        if (error) {
          console.error(error);
          return;
        }
      })
      .finally(() => {
        updateTableContents();
      });
  };

  const updateTableContents = () => {
    if (!apiUrl) {
      return;
    }
    setIsLoading(true);
    getConfigObjectList({
      apiUrl,
      offset: (page - 1) * pageSize,
      limit: pageSize
    })
      .then(([data, error]) => {
        if (error) {
          console.error(error);
          return;
        }
        setData(data);
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  const handleCreate = (obj: ConfigObject) => {
    if (!apiUrl) {
      return;
    }
    createConfigObject({
      apiUrl,
      obj
    })
      .then(([, error]) => {
        if (error) {
          console.error(error);
          return;
        }
      })
      .finally(() => {
        updateTableContents();
      });
  };

  const handleDelete = (keyId: string) => {
    if (!apiUrl) {
      return;
    }
    deleteConfigObject({
      apiUrl,
      key: keyId
    })
      .then(([, error]) => {
        if (error) {
          console.error(error);
          return;
        }
      })
      .finally(() => {
        updateTableContents();
      });
  };

  useEffect(() => {
    updateTableContents();
  }, [page, pageSize, apiUrl]);

  const pages = useMemo(() => {
    return data?.total ? Math.ceil(data.total / pageSize) : 0;
  }, [data?.total, pageSize]);

  const loadingState =
    isLoading || data?.items.length === 0 ? 'loading' : 'idle';

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col justify-between gap-3 items-end">
        <NewConfigObjectModal onSave={handleCreate} />
      </div>
      <Table
        bottomContent={
          pages > 0 ? (
            <div className="flex w-full justify-center">
              <Pagination
                isCompact
                showControls
                showShadow
                color="primary"
                page={page}
                total={pages}
                onChange={(page) => setPage(page)}
              />
            </div>
          ) : null
        }
      >
        <TableHeader>
          <TableColumn key="configKey" align="start">
            KEY
          </TableColumn>
          <TableColumn key="configValue" align="start">
            VALUE
          </TableColumn>
          <TableColumn key="configActions" align="start">
            ACTIONS
          </TableColumn>
        </TableHeader>
        <TableBody
          items={
            data?.items.map((obj) => ({
              keyId: obj.key,
              value: obj.value,
              secret: obj.secret
            })) ?? []
          }
          loadingContent={<Spinner />}
          loadingState={loadingState}
        >
          {(item) => (
            <TableRow key={item.keyId}>
              <TableCell width="200">
                <div className="flex items-center gap-1">
                  {item.secret && (
                    <Tooltip content="Stored as encrypted secret">
                      <span className="text-warning">
                        <IconLock size={14} />
                      </span>
                    </Tooltip>
                  )}
                  {item.keyId}
                </div>
              </TableCell>
              <TableCell width="400">
                {editKeyId === item.keyId ? (
                  <Input
                    width="400"
                    value={editValue ?? ''}
                    placeholder={item.secret ? 'Enter new secret value' : ''}
                    type={item.secret ? 'password' : 'text'}
                    onValueChange={setEditValue}
                  />
                ) : (
                  item.value
                )}
              </TableCell>
              <TableCell width="100">
                <div className="relative flex items-center gap-2 justify-left">
                  {editKeyId !== item.keyId && (
                    <Button
                      isIconOnly
                      color="default"
                      size="sm"
                      onPress={() => {
                        setEditKeyId(item.keyId);
                        setEditValue(item.secret ? '' : item.value);
                      }}
                    >
                      <IconPencil />
                    </Button>
                  )}
                  {editKeyId === item.keyId && (
                    <>
                      <Button
                        isIconOnly
                        color="default"
                        size="sm"
                        onPress={() => handleSaveEdit(item)}
                      >
                        <IconCheck />
                      </Button>
                      <Button
                        isIconOnly
                        color="default"
                        size="sm"
                        onPress={() => {
                          setEditValue(item.value);
                          setEditKeyId(undefined);
                        }}
                      >
                        <IconX />
                      </Button>
                    </>
                  )}
                  {!item.secret && editKeyId !== item.keyId && (
                    <Tooltip content="Mark as secret (irreversible)">
                      <Button
                        isIconOnly
                        color="warning"
                        variant="flat"
                        size="sm"
                        onPress={() => handleMarkAsSecret(item)}
                      >
                        <IconLockOpen size={16} />
                      </Button>
                    </Tooltip>
                  )}
                  <ClipBoardCopyButton
                    text={apiUrl + '/config/' + item.keyId}
                  />
                  <Button
                    isIconOnly
                    color="danger"
                    size="sm"
                    onPress={() => setConfirmModalOpen(true)}
                  >
                    <IconTrash />
                  </Button>
                  <ConfirmationModal
                    isOpen={isConfirmModalOpen}
                    setIsOpen={setConfirmModalOpen}
                    handleConfirmClick={() => handleDelete(item.keyId)}
                    modalContent={`Are you sure you want to delete this configuration variable?`}
                    buttonContent="Yes, I am sure"
                  />
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
