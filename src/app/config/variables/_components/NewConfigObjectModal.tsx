import { ConfigObject } from '@/api_config';
import {
  Button,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Switch,
  useDisclosure
} from '@nextui-org/react';
import { IconLock, IconPlus } from '@tabler/icons-react';
import { useState } from 'react';

export interface NewConfigObjectModalProps {
  onSave: (obj: ConfigObject) => void;
}

export default function NewConfigObjectModal({
  onSave
}: NewConfigObjectModalProps) {
  const { isOpen, onOpen, onOpenChange } = useDisclosure();
  const [keyId, setKeyId] = useState('');
  const [value, setValue] = useState('');
  const [isSecret, setIsSecret] = useState(false);

  return (
    <>
      <Button color="primary" onPress={onOpen} endContent={<IconPlus />}>
        Add New
      </Button>
      <Modal
        isOpen={isOpen}
        onOpenChange={(open) => {
          if (!open) {
            setIsSecret(false);
          }
          onOpenChange();
        }}
        size="xl"
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader className="flex flex-row gap-1">
                Add new configuration variable
              </ModalHeader>
              <ModalBody>
                <div className="flex flex-col text-xs gap-3">
                  <Input
                    label="Key"
                    placeholder="Enter variable name"
                    onValueChange={setKeyId}
                  />
                  <Input
                    label="Value"
                    placeholder="Enter variable value"
                    type={isSecret ? 'password' : 'text'}
                    onValueChange={setValue}
                  />
                  <Switch
                    isSelected={isSecret}
                    onValueChange={setIsSecret}
                    size="sm"
                    startContent={<IconLock size={14} />}
                  >
                    Store as secret
                  </Switch>
                </div>
              </ModalBody>
              <ModalFooter>
                <Button color="default" variant="light" onPress={onClose}>
                  Cancel
                </Button>
                <Button
                  color="primary"
                  onPress={() => {
                    onSave({
                      key: keyId,
                      value,
                      ...(isSecret ? { secret: true } : {})
                    });
                    onClose();
                  }}
                >
                  Create
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
    </>
  );
}
