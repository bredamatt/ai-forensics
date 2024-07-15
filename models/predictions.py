import torch
from simple_pytorch_nn import SimpleNN  # Ensure you have the SimpleNN definition available

# Load the model
model = SimpleNN()
model.load_state_dict(torch.load('simple_pytorch_nn_model.pth'))
model.eval()

# Dummy input data for prediction
input_data = torch.randn(1, 3, 224, 224)

# Perform prediction
with torch.no_grad():
    output = model(input_data)

print(output)

